/* cyw43439_driver.c - clean-room CYW43439 host driver
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * =============================================================
 * Bring-up sequence (CYW43439 datasheet + PicoWi reversing notes)
 * =============================================================
 *
 *   1. Assert WL_REG_ON; hold DATA2 low (not present on Pico 2 W
 *      carrier - the strap is fixed at silicon, gSPI mode is the only
 *      option) and wait >= 4.5 ms for the chip's POR sequence.
 *
 *   2. Poll the gSPI test register at F0/0x14 for the value
 *      0xFEEDBEAD (chip alive + ALP clock running). Time out after
 *      ~50 ms.
 *
 *   3. Configure the gSPI bus: 32-bit word size, little-endian, high-
 *      speed mode (CHIP_CLOCK_CSR = ALP_AVAIL | FORCE_ALP). Switch to
 *      higher clock once HT_AVAIL is set.
 *
 *   4. Enable F1 backplane access; raise the backplane window to the
 *      ARM's SRAM region (~ 0x00000000 on-chip, separate address space
 *      from the host XIP).
 *
 *   5. Push the firmware blob (~225 KB) byte-stream into the ARM's
 *      SRAM via F1 sliding-window writes. Append the NVRAM tail
 *      (typically ~1 KB of board params) and the CLM regional blob
 *      (~7 KB).
 *
 *   6. Write the reset vector to SBSDIO_FUNC1_SBADDRLOW (low PC bits)
 *      and SBADDRHIGH. Deassert the ARM reset by clearing
 *      SICF_CPUHALT and setting SICF_CLOCK_EN | SICF_FGC in the AI
 *      IOCTRL register at backplane 0x18000644 (ARM core).
 *
 *   7. Poll the firmware ready flag at the well-known F1 sentinel
 *      until ARM_RUNNING. The firmware now drives the gSPI host
 *      interface; further communication is SDPCM-framed.
 *
 *   8. Subscribe to the F2 data channel (issue an SDPCM "subscribe"
 *      ioctl) and start polling DATA_RDY for inbound events.
 *
 * SDPCM frame format (channel field selects sub-protocol):
 *
 *   +0 : length (LE u16; total bytes from start of header)
 *   +2 : length-XOR (~length, sanity check)
 *   +4 : sequence (u8, incremented each TX)
 *   +5 : channel (0 = control/ioctl, 1 = event, 2 = data)
 *   +6 : next-len (u8, flow control)
 *   +7 : header-len (u8, typically 12)
 *   +8 : padding (typically 0)
 *
 * After SDPCM there is a per-channel sub-header:
 *   ioctl  -> CDC header (cmd / flags / id / len / status, 16 bytes)
 *   data   -> BDC header (flags / priority / flags2 / data-offset,
 *             4 bytes; followed by 802.3 frame)
 *   event  -> BDC + WLC event hdr
 *
 * The WLC ioctl command numbers and the wpa_auth / wsec / event-mask /
 * BDC / wl_wsec_key constants used by the data path are #defined below;
 * the country code is set via the "country" iovar (WLC_SET_VAR), not a
 * dedicated ioctl.
 *
 * EAPOL TX: BDC frame on channel 2 with ethertype 0x888E in the body.
 * EAPOL RX: dispatched by frame type from the BDC inbound queue.
 *
 * Hardware-proven: the control plane (gSPI -> backplane -> ALP ->
 * firmware download -> SDPCM/CDC ioctl -> WLC_UP + MAC read) and the
 * join + event-driven assoc state (cyw43_connect associates to a real
 * AP; cyw43_poll decodes WLC_E_LINK up/down). Still untested on silicon:
 * the 4-way EAPOL data path + WLC_SET_KEY, which need the wolfIP
 * supplicant linked in (WOLFIP_WITH_SUPPLICANT).
 */
#include <string.h>
#include <stdio.h>

#include "cyw43439_driver.h"
#include "cyw43_sdpcm.h"
#include "rp2350_spi.h"
#include "rp2350_pio.h"
#include "cyw43439_fw.h"

/* DEBUG_BRINGUP (default 1) is defined in cyw43439_driver.h. When 0 the
 * progress logging below - calls and format strings - is compiled out. */
#if DEBUG_BRINGUP
#define BRINGUP_LOG(...) printf(__VA_ARGS__)
#else
#define BRINGUP_LOG(...) do { } while (0)
#endif

/* gSPI command frame layout - 32-bit command word.
 *   bit 31    : direction      (0 = read, 1 = write)
 *   bit 30    : auto-increment (1 = yes for multi-word access)
 *   bits 29:28: function       (0 = F0/bus, 1 = F1/backplane, 2 = F2/data)
 *   bits 27:11: address        (17-bit byte address)
 *   bits 10:0 : length         (bytes, up to 2047)
 */
#define GSPI_CMD_WRITE          (1U << 31)
#define GSPI_CMD_INC            (1U << 30)
#define GSPI_CMD_FUNC(f)        ((uint32_t)((f) & 3U) << 28)
#define GSPI_CMD_ADDR(a)        ((uint32_t)((a) & 0x1FFFFU) << 11)
#define GSPI_CMD_LEN(n)         ((uint32_t)((n) & 0x7FFU))

/* F0 (bus) registers. */
#define GSPI_F0_BUS_CTRL        0x0000U
#define GSPI_F0_RESPONSE_DELAY  0x0001U
#define GSPI_F0_BUS_TEST        0x0014U     /* expect 0xFEEDBEAD          */

/* SPI_BUS_CONTROL (F0 0x0000) field bits. */
#define BUS_WORD_LENGTH_32      (1U << 0)
#define BUS_ENDIAN_BIG          (1U << 1)
#define BUS_CLOCK_PHASE         (1U << 2)
#define BUS_CLOCK_POLARITY      (1U << 3)
#define BUS_HIGH_SPEED          (1U << 4)
#define BUS_INT_POLARITY_HIGH   (1U << 5)
#define BUS_WAKE_UP             (1U << 7)

#define GSPI_TEST_PATTERN       0xFEEDBEADU

/* Functions. */
#define GSPI_FUNC_BUS           0U          /* F0 - SPI bus registers     */
#define GSPI_FUNC_BACKPLANE     1U          /* F1 - chip backplane        */
#define GSPI_FUNC_WLAN          2U          /* F2 - WLAN data             */

/* F0 register: per-function read response delay (bytes). */
#define SPI_RESP_DELAY_F1       0x1DU       /* F0 */
#define F1_READ_PAD_BYTES       16U         /* delay we configure for F1 */

/* F1 (backplane) window-control + clock registers (direct F1 addresses,
 * accessed without the backplane window). */
#define SBSDIO_FUNC1_SBADDRLOW  0x1000AU    /* 3 consecutive bytes set the */
#define SBSDIO_FUNC1_SBADDRMID  0x1000BU    /* backplane address window     */
#define SBSDIO_FUNC1_SBADDRHIGH 0x1000CU
#define CHIP_CLOCK_CSR          0x1000EU
#define CLOCK_CSR_ALP_REQ       0x08U
#define CLOCK_CSR_HT_REQ        0x10U
#define CLOCK_CSR_ALP_AVAIL     0x40U
#define CLOCK_CSR_HT_AVAIL      0x80U

/* Backplane addressing. The low 15 bits index within a 32 KB window; the
 * upper bits select the window via the SBADDR registers. Backplane
 * memory accesses OR the 4-byte-access flag into the in-window address. */
#define BACKPLANE_WINDOW_MASK   0x7FFFU
#define SB_ACCESS_4B_FLAG       0x8000U
#define CHIPCOMMON_BASE         0x18000000U
#define CYW43_CHIP_ID           0xA9A6U      /* 43439 ChipCommon id field  */

/* Internal core wrappers (AI) for the firmware download / launch. */
#define WRAPPER_OFFSET          0x00100000U
#define WLAN_ARMCM3_BASE        0x18003000U
#define SOCSRAM_BASE            0x18004000U
#define WLAN_ARM_WRAPPER        (WLAN_ARMCM3_BASE + WRAPPER_OFFSET) /* 0x18103000 */
#define SOCSRAM_WRAPPER         (SOCSRAM_BASE + WRAPPER_OFFSET)     /* 0x18104000 */
#define AI_IOCTRL_OFFSET        0x408U
#define AI_RESETCTRL_OFFSET     0x800U
#define SICF_CLOCK_EN           0x01U
#define SICF_FGC                0x02U
#define SICF_CPUHALT            0x20U
#define AIRC_RESET              0x01U
#define SOCSRAM_BANKX_INDEX     (SOCSRAM_BASE + 0x10U)   /* = 0x18004010 */
#define SOCSRAM_BANKX_PDA       (SOCSRAM_BASE + 0x44U)   /* = 0x18004044 */

/* SDIO core + chip-clock readiness during launch. */
#define SDIO_BASE               0x18002000U
#define SDIO_INT_HOST_MASK      (SDIO_BASE + 0x24U)
#define I_HMB_SW_MASK           0x000000F0U
#define SDIO_FUNCTION2_WATERMARK 0x10008U   /* F1 */
#define SPI_F2_WATERMARK        32U
#define SPI_STATUS_REGISTER     0x08U       /* F0 */
#define STATUS_F2_RX_READY      0x20U

#define CYW43_RAM_SIZE          0x80000U    /* 512 KB chip RAM */
#define CYW43_FW_CHUNK          64U

/* F2 (WLAN data) packet transport + SDPCM/CDC ioctl framing. */
#define STATUS_F2_PKT_AVAILABLE 0x00000100U
#define STATUS_F2_PKT_LEN_MASK  0x000FFE00U
#define STATUS_F2_PKT_LEN_SHIFT 9U
#define SPI_FRAME_CONTROL       0x1000DU    /* F1 backplane: 0x1000x range */
/* gSPI F0 interrupt register: 16-bit, write-1-to-clear. The firmware gates
 * the F2 RX path until latched FIFO error bits are acknowledged, so an
 * unacked overflow during an inbound burst stalls RX permanently. */
#define SPI_INTERRUPT_REGISTER  0x04U       /* F0, 2 bytes, W1C */
#define SPI_INTERRUPT_ENABLE    0x06U       /* F0, 2 bytes */
#define SPI_INT_DATA_UNAVAIL    0x0001U
#define SPI_INT_F2F3_UNDERFLOW  0x0002U
#define SPI_INT_F2F3_OVERFLOW   0x0004U
#define SPI_INT_COMMAND_ERROR   0x0008U
#define SPI_INT_DATA_ERROR      0x0010U
#define SPI_INT_F2_PKT_AVAIL    0x0020U
#define SPI_INT_F1_OVERFLOW     0x0080U
#define SPI_INT_ERROR_BITS      (SPI_INT_DATA_UNAVAIL | SPI_INT_F2F3_UNDERFLOW \
                                 | SPI_INT_F2F3_OVERFLOW | SPI_INT_COMMAND_ERROR \
                                 | SPI_INT_DATA_ERROR | SPI_INT_F1_OVERFLOW)
/* Interrupt-enable mask written to 0x06 at init (= 0x00BE, the WHD/cyw43
 * value). The firmware only keeps re-asserting F2_PACKET_AVAILABLE in the
 * status word while F2 + its error bits are enabled here; without this the
 * F2 RX path stops flagging packets after the first FIFO error and stalls
 * permanently. */
#define SPI_INT_ENABLE_MASK     (SPI_INT_F2F3_UNDERFLOW | SPI_INT_F2F3_OVERFLOW \
                                 | SPI_INT_COMMAND_ERROR | SPI_INT_DATA_ERROR \
                                 | SPI_INT_F2_PKT_AVAIL | SPI_INT_F1_OVERFLOW)
#define SDPCM_CHAN_CONTROL      0U
#define SDPCM_CHAN_EVENT        1U
#define SDPCM_CHAN_DATA         2U
#define CDC_KIND_GET            0U
#define CDC_KIND_SET            2U
#define WLC_UP                  2U
#define WLC_DOWN                3U        /* take the MAC down for reconfig  */
#define WLC_GET_VAR             262U
#define WLC_SET_VAR             263U
#define CYW43_IOBUF_SZ          2048U

/* WLC ioctl command IDs used by the join / data path. Clean-room: these
 * are numeric command numbers of the CYW43xxx "wl" ioctl interface,
 * cross-checked across brcmfmac / WHD / cyw43-driver. */
#define WLC_SET_INFRA           20U
#define WLC_SET_AUTH            22U
#define WLC_SET_SSID            26U
#define WLC_SET_KEY             45U
#define WLC_DISASSOC            52U
#define WLC_SET_WSEC            134U
#define WLC_SET_WPA_AUTH        165U
#define WLC_SET_WSEC_PMK        268U      /* push passphrase/PMK to firmware */
#define WLC_SET_PM              86U       /* power-management mode (0=CAM)   */
#define WLC_PM_OFF              0U        /* constantly awake (no sleep)     */
#define WSEC_PASSPHRASE         0x0001U   /* wsec_pmk_t flags: key is a passphrase */

/* wpa_auth (WLC_SET_WPA_AUTH), wsec (WLC_SET_WSEC), infra + auth values. */
#define WPA_AUTH_DISABLED       0x0000U
#define WPA2_AUTH_PSK           0x0080U
#define WSEC_NONE               0x0000U
#define WSEC_AES_ENABLED        0x0004U   /* CCMP */
#define INFRA_INFRASTRUCTURE    1U
#define AUTH_OPEN               0U

/* Async event indices (WLC_E_*) + the event_msgs subscription mask. */
#define WLC_E_SET_SSID          0U
#define WLC_E_AUTH              3U
#define WLC_E_DEAUTH            5U
#define WLC_E_DEAUTH_IND        6U
#define WLC_E_ASSOC             7U
#define WLC_E_DISASSOC          11U
#define WLC_E_DISASSOC_IND      12U
#define WLC_E_LINK              16U
#define WLC_E_PSK_SUP           46U
#define WL_EVENTING_MASK_LEN    16U
#define WLC_E_STATUS_SUCCESS    0U
#define WLC_EVENT_MSG_LINK      0x01U     /* WLC_E_LINK flags: link up */
/* WLC_E_PSK_SUP status (supplicant state): the firmware's 4-way handshake
 * is fully complete and the link is encrypted only at WLC_SUP_KEYED. This
 * is the canonical "you may send data / start DHCP" trigger on a secured
 * FullMAC join - WLC_E_ASSOC (associated) and WLC_E_LINK (link up) both
 * fire while the port is still unkeyed. Wire value is 6 (cyw43-driver
 * CYW43_SUP_KEYED, brcmfmac FWSUP_COMPLETED; WHD's 262 is a host-side
 * +256 bias only, not on the wire). */
#define WLC_SUP_KEYED           6U

/* BDC (data-channel) 4-byte header. Protocol version 2 sits in the high
 * nibble of the flags byte; data_offset is in units of 4 bytes. */
#define BDC_PROTO_VER           2U
#define BDC_FLAG_VER            (BDC_PROTO_VER << 4)   /* 0x20 */

/* wl_wsec_key (WLC_SET_KEY) - 160-byte struct, selected field offsets. */
#define WSEC_KEY_STRUCT_SZ      160U
#define WSEC_KEY_OFF_INDEX      0U
#define WSEC_KEY_OFF_LEN        4U
#define WSEC_KEY_OFF_DATA       8U
#define WSEC_KEY_OFF_ALGO       112U
#define WSEC_KEY_OFF_FLAGS      116U
#define WSEC_KEY_OFF_EA         154U
#define CRYPTO_ALGO_AES_CCM     4U
#define WL_PRIMARY_KEY          2U        /* pairwise / primary key flag */

#define ETHERTYPE_EAPOL         0x888EU
#define WLC_SSID_STRUCT_SZ      36U       /* u32 len + 32-byte SSID */

/* Driver state. Small enough to keep on .bss. */
static struct cyw43_state {
    cyw43_eapol_cb_t eapol_cb;
    cyw43_data_cb_t  data_cb;
    void            *cb_ctx;
    uint8_t          mac[6];     /* our STA MAC                          */
    uint8_t          bssid[6];   /* associated AP MAC (EAPOL dst)        */
    uint8_t          tx_seq;
    int              ready;
    int              assoc_up;   /* current link state (up/down)         */
    int              assoc_seen; /* latched: link came up at least once  */
    int              keyed;      /* 4-way complete (WLC_SUP_KEYED)        */
    uint32_t         rx_count;   /* inbound data frames (liveness)        */
    uint32_t         bus_test;      /* F0 0x14 read after 32-bit config */
    uint32_t         bus_test_pre;  /* F0 0x14 read in initial swap mode */
    uint32_t         chip_id;       /* ChipCommon id (diagnostics)      */
    uint32_t         cur_window;    /* cached backplane window          */
    uint32_t         alp_csr;       /* last clock-CSR read (diagnostics)*/
    int              alp_ok;        /* ALP clock available              */
} g_cyw43;

void cyw43_set_rx_callbacks(cyw43_eapol_cb_t eapol_cb,
                            cyw43_data_cb_t  data_cb,
                            void *ctx)
{
    g_cyw43.eapol_cb = eapol_cb;
    g_cyw43.data_cb  = data_cb;
    g_cyw43.cb_ctx   = ctx;
}

/* ---- gSPI register access ----------------------------------------- *
 *
 * gSPI command word (32-bit, clocked MSB first):
 *   [31]    rw          1 = write, 0 = read
 *   [30]    increment   1 = address auto-increments across the burst
 *   [29:28] function    0 = F0 bus, 1 = F1 backplane, 2 = F2 WLAN
 *   [27:11] address     17-bit byte address
 *   [10:0]  length      byte count (1..2047)
 *
 * After WL_REG_ON the chip's gSPI comes up in 16-bit word mode with the
 * two 16-bit halves of every 32-bit quantity swapped on the wire. We use
 * the *_swap helpers to talk to it in that state just long enough to
 * write SPI_BUS_CONTROL (selecting 32-bit big-endian, high-speed), after
 * which the plain (non-swapped) helpers are correct.
 */

/* Reset-state byte order: the gSPI powers up in 16-bit mode. Sending the
 * 32-bit command MSB-first with its two 16-bit halves swapped puts the
 * documented wire byte order on the line (for cmd 0x4000A004 -> wire
 * A0 04 40 00, matching the PicoWi/cyw43-driver reference). Self-inverse,
 * so the same transform reassembles the readback. */
static uint32_t swap_le16(uint32_t w)
{
    return (w << 16) | (w >> 16);
}

/* Coarse busy-wait between test-register retries. clk_sys is pinned to
 * a known 12 MHz, so ~3M iterations ~= 1 s. */
static void busy_loop(uint32_t n)
{
    volatile uint32_t i = n;
    while (i-- != 0U) { __asm volatile("nop"); }
}

/* Build a gSPI command word. Auto-increment is always set (every access
 * in this driver is a burst). write != 0 sets the direction bit; fn picks
 * F0/F1/F2; addr is the 17-bit byte address; nbytes the burst length. */
static uint32_t gspi_cmd(int write, uint32_t fn, uint32_t addr,
                         uint32_t nbytes)
{
    return cyw43_gspi_cmd(write, fn, addr, nbytes);
}

/* Read a 32-bit register over PIO in the reset-state swapped byte order:
 * the command and the returned word both use the 16-bit-half swap. CS is
 * framed around the single PIO transaction. */
static uint32_t gspi_read32_swap(uint32_t fn, uint32_t addr)
{
    uint32_t cmd = gspi_cmd(0, fn, addr, 4U);
    uint32_t val;
    rp2350_spi_cs(1);
    val = rp2350_pio_xfer32(swap_le16(cmd), 32U, 32U);
    rp2350_spi_cs(0);
    return swap_le16(val);
}

/* Full 32-bit byte reverse. SPI_BUS_CONTROL selects 32-bit LITTLE-endian
 * mode, so once switched, the command and the returned word both go on
 * the wire LSB-byte-first - i.e. byte-reversed from our native MSB-first
 * PIO shift. (The ENDIAN bit, despite the "BIG" name, selects little.) */
static uint32_t bswap32(uint32_t w)
{
    return ((w & 0x000000FFU) << 24) | ((w & 0x0000FF00U) << 8)
         | ((w & 0x00FF0000U) >> 8)  | ((w & 0xFF000000U) >> 24);
}

/* 32-bit-mode read (after SPI_BUS_CONTROL has been written). */
static uint32_t gspi_read32(uint32_t fn, uint32_t addr)
{
    uint32_t cmd = gspi_cmd(0, fn, addr, 4U);
    uint32_t val;
    rp2350_spi_cs(1);
    val = rp2350_pio_xfer32(bswap32(cmd), 32U, 32U);
    rp2350_spi_cs(0);
    return bswap32(val);
}

/* Write a 32-bit register over PIO in the reset-state swapped byte order:
 * 64 bits out (swapped command then swapped value), then 32 dummy in-bits
 * to keep the RX FIFO balanced (the chip drives nothing on a write). */
static void gspi_write32_swap(uint32_t fn, uint32_t addr, uint32_t val)
{
    uint32_t cmd = gspi_cmd(1, fn, addr, 4U);
    uint32_t out[2];
    out[0] = swap_le16(cmd);
    out[1] = swap_le16(val);
    rp2350_spi_cs(1);
    (void)rp2350_pio_xfer(out, 2U, 64U, 32U);
    rp2350_spi_cs(0);
}

/* Bring the gSPI bus up via PIO and confirm the link by reading the test
 * register (0xFEEDBEAD) in the reset-state swapped mode, with retries
 * (the first read after power-up routinely fails while the chip settles).
 * Returns 0 on success. The 32-bit-mode bus-control write + bulk
 * transfers come next (they need multi-word PIO output); reading the
 * test register needs only this swapped read. */
static int gspi_bus_init(void)
{
    int tries;

    /* SPI_BUS_CONTROL value that selects 32-bit / high-speed mode:
     * byte0 0xB3 (WORD_LENGTH_32|ENDIAN|HIGH_SPEED|INT_POL_HIGH|WAKE_UP)
     * + INTR_WITH_STATUS in the status byte (offset 0x02) = 0x000200B3. */
    uint32_t ctrl = BUS_WORD_LENGTH_32 | BUS_ENDIAN_BIG | BUS_HIGH_SPEED
                  | BUS_INT_POLARITY_HIGH | BUS_WAKE_UP | (0x02U << 16);

    g_cyw43.bus_test_pre = 0;
    for (tries = 0; tries < 64; tries++) {
        g_cyw43.bus_test_pre =
            gspi_read32_swap(GSPI_FUNC_BUS, GSPI_F0_BUS_TEST);
        if (g_cyw43.bus_test_pre == GSPI_TEST_PATTERN) {
            break;
        }
        busy_loop(60000U);           /* ~20 ms gap between attempts */
    }
    if (g_cyw43.bus_test_pre != GSPI_TEST_PATTERN) {
        g_cyw43.bus_test = 0;
        return -1;                   /* no link */
    }

    /* Switch to 32-bit mode (write is done in the still-swapped order),
     * then confirm with a PLAIN (unswapped) test-register read. A
     * 0xFEEDBEAD here proves the bus-control write landed and we are now
     * in 32-bit mode - the gateway to backplane + firmware load. */
    gspi_write32_swap(GSPI_FUNC_BUS, GSPI_F0_BUS_CTRL, ctrl);
    g_cyw43.bus_test = gspi_read32(GSPI_FUNC_BUS, GSPI_F0_BUS_TEST);
    return (g_cyw43.bus_test == GSPI_TEST_PATTERN) ? 0 : -1;
}

uint32_t cyw43_last_bus_test(void)     { return g_cyw43.bus_test; }
uint32_t cyw43_last_bus_test_pre(void) { return g_cyw43.bus_test_pre; }
uint32_t cyw43_last_chip_id(void)      { return g_cyw43.chip_id; }
int      cyw43_last_alp_ok(void)       { return g_cyw43.alp_ok; }
uint32_t cyw43_last_alp_csr(void)      { return g_cyw43.alp_csr; }

/* ---- 32-bit-mode register + backplane access ---------------------- *
 *
 * In 32-bit little-endian mode the command and data go on the wire LSB
 * byte first, which is byte-reversed from our native MSB-first PIO shift,
 * so we bswap32 both. A write of N(<=4) bytes packs the bytes with byte0
 * (lowest address) in bits[7:0] of `val`; bswap32 then places byte0 in
 * the MSB position so PIO sends it first. F1 (backplane) reads need a
 * 16-byte response pad (SPI_RESP_DELAY_F1); F0 reads need none.
 */

/* Direct register write of nbytes (1..4) to function fn at addr. The
 * command length is the real byte count, but we always clock a full
 * 32-bit data word (out_bits = 64, a multiple of 32 - required by the
 * PIO transport). The chip writes only `nbytes` and ignores the extra
 * clocked bytes (same as cyw43-driver's 4-byte alignment). */
static void gspi_reg_write(uint32_t fn, uint32_t addr, uint32_t val,
                           uint32_t nbytes)
{
    uint32_t cmd = gspi_cmd(1, fn, addr, nbytes);
    uint32_t out[2];
    out[0] = bswap32(cmd);
    out[1] = bswap32(val);
    rp2350_spi_cs(1);
    (void)rp2350_pio_xfer(out, 2U, 64U, 32U);
    rp2350_spi_cs(0);
}

/* Direct 4-byte register read from function fn at addr, with `pad_bytes`
 * of read turnaround (0 for F0/F2, F1_READ_PAD_BYTES for F1). Returns the
 * 32-bit value (LE: byte at addr in bits[7:0]). */
static uint32_t gspi_reg_read(uint32_t fn, uint32_t addr, uint32_t pad_bytes)
{
    uint32_t cmd = gspi_cmd(0, fn, addr, 4U);
    uint32_t cmd_w = bswap32(cmd);
    uint32_t val;
    rp2350_spi_cs(1);
    /* Clock pad bytes then 4 data bytes; the PIO returns the last word. */
    val = rp2350_pio_xfer(&cmd_w, 1U, 32U, (pad_bytes + 4U) * 8U);
    rp2350_spi_cs(0);
    return bswap32(val);
}

/* Read the F0 SPI interrupt register and write back (W1C) any latched FIFO
 * or bus error bits. The chip stops asserting F2 packet-available until an
 * overflow/underflow is acknowledged this way; without it the RX path
 * wedges after a burst (the AP's frame flood) and never recovers. The
 * low 16 bits at 0x04 are the status; 0x06 (enable) is read alongside but
 * ignored. */
static void gspi_service_irq(void)
{
    uint32_t ir = gspi_reg_read(GSPI_FUNC_BUS, SPI_INTERRUPT_REGISTER, 0U)
                  & SPI_INT_ERROR_BITS;
    if (ir != 0U) {
        /* W1C-acknowledge the latched error bits. */
        gspi_reg_write(GSPI_FUNC_BUS, SPI_INTERRUPT_REGISTER, ir, 2U);
        /* On a FIFO over/underflow the in-flight F2 frame is corrupt and
         * the RX path stays gated until it is flushed. Acknowledging the
         * interrupt alone is not enough - also abort the frame (frame-
         * control bit 0), the reference recovery for a wedged F2. */
        if ((ir & (SPI_INT_F2F3_OVERFLOW | SPI_INT_F2F3_UNDERFLOW)) != 0U) {
            gspi_reg_write(GSPI_FUNC_BACKPLANE, SPI_FRAME_CONTROL, 1U, 1U);
        }
        BRINGUP_LOG("  [irq] cleared 0x%02X\n", (unsigned)ir);
    }
}

/* Point the backplane window at the 32 KB region containing `addr`. The
 * three SBADDR bytes hold addr>>8 / >>16 / >>24; written as one 3-byte
 * F1 register write. Cached to skip redundant updates. */
static void set_backplane_window(uint32_t addr)
{
    uint32_t win = addr & ~BACKPLANE_WINDOW_MASK;
    uint32_t v;
    if (win == g_cyw43.cur_window) {
        return;
    }
    v = ((addr >> 8) & 0xFFU)
      | (((addr >> 16) & 0xFFU) << 8)
      | (((addr >> 24) & 0xFFU) << 16);
    gspi_reg_write(GSPI_FUNC_BACKPLANE, SBSDIO_FUNC1_SBADDRLOW, v, 3U);
    g_cyw43.cur_window = win;
}

/* 32-bit backplane memory read/write through the window. */
static uint32_t backplane_read32(uint32_t addr)
{
    set_backplane_window(addr);
    return gspi_reg_read(GSPI_FUNC_BACKPLANE,
                         (addr & BACKPLANE_WINDOW_MASK) | SB_ACCESS_4B_FLAG,
                         F1_READ_PAD_BYTES);
}

/* Bring up backplane access + the ALP clock. Reads the ChipCommon chip
 * id (0xA9A6 for 43439) to prove the window + F1 path work, then requests
 * and waits for the ALP clock. Returns 0 on success. */
static int backplane_bringup(void)
{
    int i;

    /* Tell the chip to insert F1_READ_PAD_BYTES of response delay on F1
     * reads (must match the pad we clock in gspi_reg_read). */
    gspi_reg_write(GSPI_FUNC_BUS, SPI_RESP_DELAY_F1, F1_READ_PAD_BYTES, 1U);
    g_cyw43.cur_window = 0xFFFFFFFFU;        /* force first window write */

    /* ALP clock FIRST: the backplane cores (ChipCommon etc.) are not
     * clocked - and so not readable - until ALP is available. The clock
     * CSR itself is in the always-on domain, writable/readable without
     * ALP. Request ALP and poll for availability (~10 ms). */
    BRINGUP_LOG("  [bp] resp-delay set, requesting ALP\n");
    gspi_reg_write(GSPI_FUNC_BACKPLANE, CHIP_CLOCK_CSR,
                   CLOCK_CSR_ALP_REQ, 1U);
    for (i = 0; i < 32; i++) {
        g_cyw43.alp_csr = gspi_reg_read(GSPI_FUNC_BACKPLANE, CHIP_CLOCK_CSR,
                                        F1_READ_PAD_BYTES) & 0xFFU;
        if ((g_cyw43.alp_csr & CLOCK_CSR_ALP_AVAIL) != 0U) {
            g_cyw43.alp_ok = 1;
            break;
        }
        busy_loop(60000U);
    }
    BRINGUP_LOG("  [bp] ALP csr=0x%02lX ok=%d\n",
           (unsigned long)g_cyw43.alp_csr, g_cyw43.alp_ok);

    /* ChipCommon id (now that ALP clocks the backplane) - diagnostic
     * proof that the window + F1 read path work. Not fatal. */
    g_cyw43.chip_id = backplane_read32(CHIPCOMMON_BASE) & 0xFFFFU;
    BRINGUP_LOG("  [bp] chip id=0x%04lX\n", (unsigned long)g_cyw43.chip_id);

    return g_cyw43.alp_ok ? 0 : -1;
}

/* ---- firmware download ---------------------------------------------- *
 *
 * The CYW43439 firmware/CLM/NVRAM blob is not part of this repo (third-
 * party license, RP-silicon only). These accessors are weak so the build
 * links without it; the git-ignored fw_local/cyw43_fw_blob.c provides the
 * strong versions when present. NULL => firmware download is skipped.
 */
__attribute__((weak)) const uint8_t *cyw43_blob_fw(size_t *len)
{ if (len) *len = 0; return 0; }
__attribute__((weak)) const uint8_t *cyw43_blob_clm(size_t *len)
{ if (len) *len = 0; return 0; }
__attribute__((weak)) const uint8_t *cyw43_blob_nvram(size_t *len)
{ if (len) *len = 0; return 0; }

static void backplane_write32(uint32_t addr, uint32_t val)
{
    set_backplane_window(addr);
    gspi_reg_write(GSPI_FUNC_BACKPLANE,
                   (addr & BACKPLANE_WINDOW_MASK) | SB_ACCESS_4B_FLAG,
                   val, 4U);
}

/* Write `len` bytes of `data` to backplane RAM at `addr`, in 64-byte
 * chunks. Each 4 source bytes pack big-endian into a PIO out word so the
 * PIO (MSB-first) emits them to ascending RAM addresses; the last partial
 * chunk is zero-padded to 64 bytes. */
static void bulk_backplane_write(uint32_t addr, const uint8_t *data,
                                 uint32_t len)
{
    uint32_t off;
    for (off = 0; off < len; off += CYW43_FW_CHUNK) {
        uint32_t dst = addr + off;
        uint32_t chunk = (len - off < CYW43_FW_CHUNK)
                         ? (len - off) : CYW43_FW_CHUNK;
        uint32_t out[1U + (CYW43_FW_CHUNK / 4U)];
        uint32_t cmd, w, i;
        uint8_t  b[4];
        uint32_t idx;
        set_backplane_window(dst);
        cmd = gspi_cmd(1, GSPI_FUNC_BACKPLANE,
                       (dst & BACKPLANE_WINDOW_MASK) | SB_ACCESS_4B_FLAG,
                       CYW43_FW_CHUNK);
        out[0] = bswap32(cmd);
        for (w = 0; w < CYW43_FW_CHUNK / 4U; w++) {
            for (i = 0; i < 4U; i++) {
                idx = off + w * 4U + i;
                b[i] = (idx < len && (w * 4U + i) < chunk) ? data[idx] : 0U;
            }
            out[1U + w] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                        | ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
        }
        rp2350_spi_cs(1);
        (void)rp2350_pio_xfer(out, 1U + (CYW43_FW_CHUNK / 4U),
                              32U + CYW43_FW_CHUNK * 8U, 32U);
        rp2350_spi_cs(0);
    }
}

/* ---- AI core control ---- */

static uint32_t ai_read(uint32_t wrapper, uint32_t off)
{
    return backplane_read32(wrapper + off);
}
static void ai_write(uint32_t wrapper, uint32_t off, uint32_t val)
{
    backplane_write32(wrapper + off, val);
}

/* Put a core into reset (no-op if the device powered up already in
 * reset, which is the normal case). */
static void core_disable(uint32_t wrapper)
{
    if ((ai_read(wrapper, AI_RESETCTRL_OFFSET) & AIRC_RESET) != 0U) {
        return;                       /* already in reset */
    }
    ai_write(wrapper, AI_IOCTRL_OFFSET, SICF_FGC | SICF_CLOCK_EN);
    (void)ai_read(wrapper, AI_IOCTRL_OFFSET);
    ai_write(wrapper, AI_RESETCTRL_OFFSET, AIRC_RESET);
    (void)ai_read(wrapper, AI_RESETCTRL_OFFSET);
    ai_write(wrapper, AI_IOCTRL_OFFSET, SICF_FGC);
    (void)ai_read(wrapper, AI_IOCTRL_OFFSET);
}

/* Take a core out of reset (launches the WLAN ARM after fw load). */
static void core_reset(uint32_t wrapper)
{
    core_disable(wrapper);
    ai_write(wrapper, AI_IOCTRL_OFFSET, SICF_FGC | SICF_CLOCK_EN);
    (void)ai_read(wrapper, AI_IOCTRL_OFFSET);
    ai_write(wrapper, AI_RESETCTRL_OFFSET, 0U);
    busy_loop(60000U);                /* ~20 ms (>> 1 ms) */
    ai_write(wrapper, AI_IOCTRL_OFFSET, SICF_CLOCK_EN);
    (void)ai_read(wrapper, AI_IOCTRL_OFFSET);
    busy_loop(60000U);
}

static int core_is_up(uint32_t wrapper)
{
    if ((ai_read(wrapper, AI_IOCTRL_OFFSET) & (SICF_FGC | SICF_CLOCK_EN))
        != SICF_CLOCK_EN) {
        return 0;
    }
    return ((ai_read(wrapper, AI_RESETCTRL_OFFSET) & AIRC_RESET) == 0U) ? 1 : 0;
}

/* Download firmware + NVRAM into chip RAM and launch the WLAN ARM, then
 * wait for HT clock and F2 (WLAN data channel) ready. Returns 0 on
 * success, -2 if no firmware blob is linked in. */
static int download_firmware(void)
{
    const uint8_t *fw, *nvram;
    size_t fw_len = 0, nvram_len = 0;
    uint32_t nvram_words, nvram_dst, size_word;
    int i;

    fw    = cyw43_blob_fw(&fw_len);
    nvram = cyw43_blob_nvram(&nvram_len);
    if (fw == 0 || fw_len == 0 || nvram == 0 || nvram_len == 0) {
        return -2;                    /* blob not linked in */
    }

    BRINGUP_LOG("  [fw] cores: disabling WLAN_ARM + SOCSRAM\n");
    /* Cores into a known state before loading. */
    core_disable(WLAN_ARM_WRAPPER);
    core_disable(SOCSRAM_WRAPPER);
    core_reset(SOCSRAM_WRAPPER);
    backplane_write32(SOCSRAM_BANKX_INDEX, 0x3U);
    backplane_write32(SOCSRAM_BANKX_PDA, 0U);

    /* Firmware to RAM base 0. */
    BRINGUP_LOG("  [fw] writing %u bytes to RAM 0...\n", (unsigned)fw_len);
    bulk_backplane_write(0x0U, fw, (uint32_t)fw_len);
    BRINGUP_LOG("  [fw] firmware written, NVRAM next\n");

    /* NVRAM at the top of RAM, 4-byte aligned, followed by the size word
     * (low half = word count, high half = its 16-bit complement). */
    nvram_words = ((uint32_t)nvram_len + 3U) / 4U;
    nvram_dst   = CYW43_RAM_SIZE - 4U - nvram_words * 4U;
    bulk_backplane_write(nvram_dst, nvram, (uint32_t)nvram_len);
    size_word = ((~nvram_words & 0xFFFFU) << 16) | (nvram_words & 0xFFFFU);
    backplane_write32(CYW43_RAM_SIZE - 4U, size_word);

    /* Launch the WLAN ARM. */
    BRINGUP_LOG("  [fw] launching WLAN ARM\n");
    core_reset(WLAN_ARM_WRAPPER);
    if (!core_is_up(WLAN_ARM_WRAPPER)) {
        BRINGUP_LOG("  [fw] WLAN ARM core not up\n");
        return -1;
    }
    BRINGUP_LOG("  [fw] ARM up, waiting HT clock\n");

    /* Wait for the HT clock (firmware running). */
    for (i = 0; i < 200; i++) {
        uint32_t csr = gspi_reg_read(GSPI_FUNC_BACKPLANE, CHIP_CLOCK_CSR,
                                     F1_READ_PAD_BYTES) & 0xFFU;
        if ((csr & CLOCK_CSR_HT_AVAIL) != 0U) {
            break;
        }
        busy_loop(60000U);
    }

    /* Enable host mailbox int + F2 watermark, then wait for F2 ready. */
    backplane_write32(SDIO_INT_HOST_MASK, I_HMB_SW_MASK);
    gspi_reg_write(GSPI_FUNC_BACKPLANE, SDIO_FUNCTION2_WATERMARK,
                   SPI_F2_WATERMARK, 1U);
    /* Clear any stale latched errors, then enable the SPI interrupt mask
     * (F0 0x06). Even though RX is polled, the firmware only keeps
     * re-asserting F2_PACKET_AVAILABLE while F2 + its FIFO-error bits are
     * enabled here - without it the F2 path stops flagging packets after the
     * first overflow and RX stalls permanently. */
    gspi_reg_write(GSPI_FUNC_BUS, SPI_INTERRUPT_REGISTER, SPI_INT_ERROR_BITS, 2U);
    gspi_reg_write(GSPI_FUNC_BUS, SPI_INTERRUPT_ENABLE, SPI_INT_ENABLE_MASK, 2U);
    BRINGUP_LOG("  [fw] waiting F2 ready\n");
    for (i = 0; i < 200; i++) {
        uint32_t st = gspi_reg_read(GSPI_FUNC_BUS, SPI_STATUS_REGISTER, 0U);
        if ((st & STATUS_F2_RX_READY) != 0U) {
            g_cyw43.ready = 1;
            BRINGUP_LOG("  [fw] F2 ready, status=0x%08lX\n", (unsigned long)st);
            return 0;
        }
        busy_loop(60000U);
    }
    BRINGUP_LOG("  [fw] F2 not ready (timeout)\n");
    return -1;
}

int cyw43_firmware_ready(void) { return g_cyw43.ready; }

int cyw43_init(void)
{
    g_cyw43.tx_seq = 0;
    g_cyw43.ready  = 0;
    /* SDPCM flow control (g_tx_seq/g_tx_max/g_flow_ctl) is initialised by
     * its static initialisers - one credit until the first RX. */

    /* 1. Power sequence. The CYW43439 needs a LONG settle after WL_REG_ON
     *    goes high before its gSPI core is clocked - PicoWi waits 50 ms,
     *    cyw43-driver 250 ms; too short makes the chip ignore commands.
     *    clk_sys is pinned to a known 12 MHz, so these busy_loop counts
     *    have a real duration (~4 cycles/iter -> ~3M iters ~= 1 s), and
     *    the retry loop in gspi_bus_init adds more. CS + WL_REG_ON are
     *    CPU GPIOs (rp2350_spi.c); CLK + DATA are driven by PIO. */
    rp2350_spi_init();              /* WL_REG_ON low, CS high              */
    rp2350_pio_init();              /* load PIO gSPI program on CLK/DATA   */
    busy_loop(200000U);             /* ~65 ms low settle                   */
    rp2350_cyw43_power_up();        /* WL_REG_ON high                      */
    busy_loop(4000000U);            /* ~1.3 s settle (>> 250 ms needed)    */

    /* 2. gSPI handshake over PIO: read the test register (0xFEEDBEAD) in
     *    the reset-state swapped mode, then switch to 32-bit mode. */
    if (gspi_bus_init() != 0) {
        return -1;
    }

    /* 3. Backplane access + ALP clock: prove F1 window reads work via the
     *    ChipCommon id, then bring the ALP clock up (needed to clock the
     *    backplane for the firmware download). */
    if (backplane_bringup() != 0) {
        return -1;
    }

    /* 4. Download firmware + NVRAM, launch the WLAN ARM, wait for the F2
     *    data channel. Returns -2 if no blob is linked in (the chip stays
     *    at the backplane-ready stage; ioctls/CLM/scan come next). */
    return download_firmware();
}

/* ---- SDPCM / CDC ioctl transport over F2 ---------------------------- */

static uint8_t  g_iobuf[CYW43_IOBUF_SZ];
static uint16_t g_ioctl_id;
static uint8_t  g_tx_seq;

/* Compiler-resistant zeroization for cleartext secrets (the PSK passphrase).
 * wolfCrypt's ForceZero is not linked into the non-supplicant build of this
 * port, so use a local volatile-store loop the optimizer cannot elide. */
static void cyw43_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n-- > 0U) {
        *v++ = 0U;
    }
}
/* SDPCM bus flow control. The firmware grants a TX window via the
 * bus_data_credit byte (SDPCM header +9) and can pause all TX via the
 * wireless_flow_control byte (+8). Init: one credit until the first RX
 * updates it. All arithmetic is modulo-256. */
static uint8_t  g_tx_max = 1U;   /* max tx_seq the firmware grants       */
static uint8_t  g_flow_ctl;      /* nonzero = firmware paused host TX     */

static void wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Write the 12-byte SDPCM software header for a `total`-byte frame on
 * channel `chan`. Bytes 6 and 8..11 stay 0 (caller zeroes the buffer). */
static void sdpcm_hdr(uint8_t *buf, uint8_t chan, uint32_t total)
{
    cyw43_sdpcm_hdr(buf, chan, total, g_tx_seq);
    g_tx_seq++;
}

/* Write a buffer to F2 (padded to 4 bytes). */
static void f2_write(const uint8_t *buf, uint32_t len)
{
    uint32_t plen = (len + 3U) & ~3U;
    uint32_t cmd = gspi_cmd(1, GSPI_FUNC_WLAN, 0U, plen);
    rp2350_spi_cs(1);
    rp2350_pio_write_bytes(bswap32(cmd), buf, plen);
    rp2350_spi_cs(0);
}

/* Read `len` bytes (padded to 4) from F2 into buf. */
static void f2_read(uint8_t *buf, uint32_t len)
{
    uint32_t plen = (len + 3U) & ~3U;
    uint32_t cmd = gspi_cmd(0, GSPI_FUNC_WLAN, 0U, plen);
    rp2350_spi_cs(1);
    rp2350_pio_read_bytes(bswap32(cmd), buf, plen);
    rp2350_spi_cs(0);
}

/* ---- SDPCM bus flow control --------------------------------------- *
 * The firmware never NAKs: if the host sends past its granted TX window
 * the frame is silently dropped. So we MUST track the credit (+9) and
 * flow byte (+8) from every received SDPCM header and gate every TX. */

/* Update credit/flow from a received SDPCM header `hdr`. The credit is
 * only advanced if the jump is sane (<= 0x40) to ignore garbage. */
static void sdpcm_update_credit(const uint8_t *hdr)
{
    cyw43_sdpcm_credit_update(hdr[8], hdr[9], &g_tx_max, &g_flow_ctl);
#if DEBUG_BRINGUP
    {
        static int n;
        if (n < 16) {
            n++;
            BRINGUP_LOG("  [cr] flow=%u credit=%u tx_max=%u tx_seq=%u\n",
                        (unsigned)hdr[8], (unsigned)hdr[9],
                        (unsigned)g_tx_max, (unsigned)g_tx_seq);
        }
    }
#endif
}

/* 1 if the host may transmit now: not flow-paused and tx_seq is inside
 * the granted window (modulo-256, not wrapped negative). */
static int sdpcm_tx_ready(void)
{
    return cyw43_sdpcm_tx_ready(g_tx_max, g_tx_seq, g_flow_ctl);
}

/* Send a CDC ioctl and wait for the matching response. `data` is the
 * request payload (SET) or the var name (iovar GET) on input, and the
 * response is copied back into it (up to `len`). Returns the CDC status
 * (0 = success), or -1 on transport timeout. */
static int cyw43_ioctl(uint32_t cmd, int set, uint8_t *data, uint32_t len)
{
    uint32_t total = 12U + 16U + len;
    uint16_t id    = ++g_ioctl_id;
    uint32_t flags = ((uint32_t)id << 16) | (set ? CDC_KIND_SET : CDC_KIND_GET);
    uint32_t st, rlen, rflags, rstatus, poff, avail;
    uint16_t size, size_com;
    uint8_t  chan, hlen;
    int      i;

    if (total > CYW43_IOBUF_SZ || len > 0xFFFFU) {
        /* len > 0xFFFF would be truncated by the 16-bit CDC length field below
         * while the memcpy uses the full len; reject it (unreachable while
         * CYW43_IOBUF_SZ < 0xFFFF, but explicit for clarity). */
        return -1;
    }
    /* ioctls are not credit-gated: the join sequence fits the initial
     * window + event-driven refreshes, and gating them stalls on the
     * no-reply bsscfg sets. Only the sustained DATA path is gated. */
    memset(g_iobuf, 0, (total + 3U) & ~3U);
    sdpcm_hdr(g_iobuf, SDPCM_CHAN_CONTROL, total);
    /* CDC header. */
    wr32le(&g_iobuf[12], cmd);
    wr32le(&g_iobuf[16], len & 0xFFFFU);
    wr32le(&g_iobuf[20], flags);
    if (len) {
        memcpy(&g_iobuf[28], data, len);
    }
    f2_write(g_iobuf, total);

    /* Poll for the response. Must be generous: a too-short cap can miss a
     * slightly-delayed reply, leaving it in the F2 queue and desyncing the
     * SDPCM stream (which then wedges every later ioctl). The bsscfg sets
     * that never reply just pay this as a one-time per-call cost. */
    for (i = 0; i < 500; i++) {
        gspi_service_irq();   /* keep F2 un-gated while awaiting the reply */
        st = gspi_reg_read(GSPI_FUNC_BUS, SPI_STATUS_REGISTER, 0U);
        if (st == 0xFFFFFFFFU || (st & STATUS_F2_PKT_AVAILABLE) == 0U) {
            busy_loop(20000U);
            continue;
        }
        rlen = (st & STATUS_F2_PKT_LEN_MASK) >> STATUS_F2_PKT_LEN_SHIFT;
        if (!cyw43_sdpcm_rlen_ok(rlen, CYW43_IOBUF_SZ)) {
            /* Abort a bad frame and keep polling (same padded-length guard as
             * cyw43_poll). */
            gspi_reg_write(GSPI_FUNC_BACKPLANE, SPI_FRAME_CONTROL, 1U, 1U);
            continue;
        }
        f2_read(g_iobuf, rlen);
        size = rd16le(&g_iobuf[0]);
        size_com = rd16le(&g_iobuf[2]);
        if ((uint16_t)(size ^ size_com) != 0xFFFFU || size == 0U) {
            continue;
        }
        /* The SDPCM-declared length must not exceed the bytes actually clocked
         * into g_iobuf; otherwise the field reads/copy-back below would pick up
         * stale prior-frame residue (mirrors the guard in cyw43_poll). */
        if ((uint32_t)size > rlen) {
            continue;
        }
        sdpcm_update_credit(g_iobuf);     /* refresh TX window from RX */
        chan = g_iobuf[5] & 0x0FU;
        hlen = g_iobuf[7];
        /* Event/data packets before our response are ignored here (they
         * get dispatched once the data path lands). */
        if (chan != SDPCM_CHAN_CONTROL || (uint32_t)hlen + 16U > size) {
            busy_loop(20000U);
            continue;
        }
        rflags = rd32le(&g_iobuf[hlen + 8U]);
        rstatus = rd32le(&g_iobuf[hlen + 12U]);
        if ((uint16_t)(rflags >> 16) != id) {
            busy_loop(20000U);
            continue;
        }
        if (len) {
            poff = (uint32_t)hlen + 16U;
            avail = (size > poff) ? (size - poff) : 0U;
            memcpy(data, &g_iobuf[poff], (avail < len) ? avail : len);
        }
        return (int)rstatus;
    }
    return -1;
}

/* iovar (WLC_SET_VAR/GET_VAR) helpers. The wire payload is the NUL-
 * terminated var name followed by the value bytes. */
static int set_iovar(const char *name, const uint8_t *val, uint32_t vlen)
{
    uint8_t  buf[128];
    uint32_t outlen;
    if (cyw43_iovar_build(name, val, vlen, buf, sizeof(buf), &outlen) != 0) {
        return -1;
    }
    return cyw43_ioctl(WLC_SET_VAR, 1, buf, outlen);
}

static int set_iovar_u32(const char *name, uint32_t v)
{
    uint8_t val[4];
    wr32le(val, v);
    return set_iovar(name, val, 4U);
}

/* CLM (regulatory) blob download via the clmload iovar. 1 KB chunks with
 * BEGIN/END flags; verified through clmload_status. No-op (success) when
 * no CLM blob is linked in. */
#define CLM_FLAG_HANDLER_VER 0x1000U
#define CLM_FLAG_BEGIN       0x0002U
#define CLM_FLAG_END         0x0004U
#define CLM_CHUNK            1024U
static uint8_t g_clmbuf[CLM_CHUNK + 32U];

static int clm_load(void)
{
    size_t clm_len = 0;
    const uint8_t *clm = cyw43_blob_clm(&clm_len);
    uint32_t off, st_word;
    uint8_t  stbuf[64];
    int rc;

    if (clm == 0 || clm_len == 0) {
        return 0;                       /* no CLM linked - skip */
    }
    for (off = 0; off < (uint32_t)clm_len; ) {
        uint32_t chunk = ((uint32_t)clm_len - off > CLM_CHUNK)
                         ? CLM_CHUNK : ((uint32_t)clm_len - off);
        uint16_t flag = CLM_FLAG_HANDLER_VER;
        if (off == 0U) flag |= CLM_FLAG_BEGIN;
        if (off + chunk >= (uint32_t)clm_len) flag |= CLM_FLAG_END;
        memcpy(g_clmbuf, "clmload", 8);            /* name + NUL */
        g_clmbuf[8] = (uint8_t)flag; g_clmbuf[9] = (uint8_t)(flag >> 8);
        g_clmbuf[10] = 0x02; g_clmbuf[11] = 0x00;
        wr32le(&g_clmbuf[12], chunk);
        wr32le(&g_clmbuf[16], 0U);
        memcpy(&g_clmbuf[20], clm + off, chunk);
        rc = cyw43_ioctl(WLC_SET_VAR, 1, g_clmbuf, 20U + chunk);
        if (rc != 0) return rc;
        off += chunk;
    }
    memset(stbuf, 0, sizeof(stbuf));
    memcpy(stbuf, "clmload_status", 15);
    rc = cyw43_ioctl(WLC_GET_VAR, 0, stbuf, sizeof(stbuf));
    if (rc != 0) return rc;
    st_word = rd32le(stbuf);
    return (st_word == 0U) ? 0 : -1;
}

int cyw43_wifi_up(const char *country)
{
    uint8_t     buf[64];
    uint8_t     cval[12];
    const char *cc;
    uint16_t    code;
    int         rc;

    /* CLM regulatory blob first (needed before RF operation). */
    rc = clm_load();
    BRINGUP_LOG("  [io] CLM load rc=%d\n", rc);
    if (rc != 0) {
        return -1;
    }

    /* Country code: "country" iovar = ccode(low16) + rev(-1) + ccode. */
    cc   = (country != NULL && country[0] != '\0') ? country : "XX";
    code = (uint16_t)((uint8_t)cc[0] | ((uint16_t)(uint8_t)cc[1] << 8));
    wr32le(&cval[0], code);
    wr32le(&cval[4], 0xFFFFFFFFU);
    wr32le(&cval[8], code);
    rc = set_iovar("country", cval, sizeof(cval));
    BRINGUP_LOG("  [io] set country %c%c rc=%d\n", cc[0], cc[1], rc);

    /* A couple of standard tuning iovars (best-effort). */
    (void)set_iovar_u32("bus:txglom", 0U);
    (void)set_iovar_u32("apsta", 1U);

    /* WLC_UP - bring the MAC online (no payload). */
    rc = cyw43_ioctl(WLC_UP, 1, 0, 0U);
    BRINGUP_LOG("  [io] WLC_UP rc=%d\n", rc);
    if (rc != 0) {
        return -1;
    }

    /* Read the STA MAC via the cur_etheraddr iovar to confirm the ioctl
     * round-trip works end to end. */
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "cur_etheraddr", 14);     /* name + NUL */
    rc = cyw43_ioctl(WLC_GET_VAR, 0, buf, sizeof(buf));
    if (rc == 0) {
        memcpy(g_cyw43.mac, buf, 6);
        BRINGUP_LOG("  [io] MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
               g_cyw43.mac[0], g_cyw43.mac[1], g_cyw43.mac[2],
               g_cyw43.mac[3], g_cyw43.mac[4], g_cyw43.mac[5]);
    }
    else {
        BRINGUP_LOG("  [io] get MAC rc=%d\n", rc);
    }
    return rc;
}

/* Set the firmware power-management mode (WLC_SET_PM). Pass WLC_PM_OFF to
 * keep the radio constantly awake (CAM) so inbound frames are delivered
 * continuously - the firmware otherwise sleeps in a power-saving mode and
 * the AP-buffered unicast trickles through erratically, which looks like an
 * intermittent RX stall. Firmware resets PM on each (re)association, so this
 * must be (re)applied AFTER the link is up. */
int cyw43_set_powersave(uint32_t pm)
{
    uint8_t buf[4];
    int     rc;
    wr32le(buf, pm);
    rc = cyw43_ioctl(WLC_SET_PM, 1, buf, sizeof(buf));
    BRINGUP_LOG("  [io] set_pm %lu rc=%d\n", (unsigned long)pm, rc);
    return rc;
}

/* ---- data path: join, EAPOL/802.3 TX, inbound poll ----------------- *
 *
 * NOTE: this whole data path is written from the clean-room protocol
 * facts but has NOT yet been exercised on silicon (the control plane up
 * through WLC_UP + MAC read is hardware-proven; the join handshake, BDC
 * framing and key install are the Monday bring-up milestone). Treat the
 * exact iovar names / event-flag handling as the first thing to probe.
 */

/* Async events we subscribe to so cyw43_poll() can track assoc state. */
static const uint8_t cyw43_event_subs[] = {
    WLC_E_SET_SSID, WLC_E_AUTH, WLC_E_DEAUTH, WLC_E_DEAUTH_IND,
    WLC_E_ASSOC, WLC_E_DISASSOC, WLC_E_DISASSOC_IND, WLC_E_LINK,
    WLC_E_PSK_SUP
};

/* Canonical WPA2-PSK / CCMP RSN information element (no MFP). Published
 * to the assoc request via the wpaie iovar. This MUST match the RSN IE
 * the wolfIP supplicant advertises (rsn_ie_build_wpa2_psk with MFP off)
 * so the AP's M3 RSN-IE comparison and the 4-way succeed; if the
 * supplicant enables MFP, the IE has to be plumbed from it instead. */
static const uint8_t cyw43_rsn_ie_wpa2_psk[] = {
    0x30, 0x14,                   /* RSN element, length 20             */
    0x01, 0x00,                   /* version 1                          */
    0x00, 0x0F, 0xAC, 0x04,       /* group cipher = CCMP                */
    0x01, 0x00,                   /* pairwise count 1                   */
    0x00, 0x0F, 0xAC, 0x04,       /* pairwise = CCMP                    */
    0x01, 0x00,                   /* AKM count 1                        */
    0x00, 0x0F, 0xAC, 0x02,       /* AKM = PSK                          */
    0x00, 0x00                    /* RSN capabilities                   */
};

/* Backing store for the 160-byte wl_wsec_key (kept off the stack). */
static uint8_t g_keybuf[WSEC_KEY_STRUCT_SZ];

/* Send a bare u32 argument to a WLC command (not an iovar). */
static int cyw43_ioctl_set_u32(uint32_t cmd, uint32_t v)
{
    uint8_t b[4];
    wr32le(b, v);
    return cyw43_ioctl(cmd, 1, b, 4U);
}

/* Build an SDPCM (data channel) + BDC frame from an optional synthetic
 * Ethernet header plus a payload, and push it on F2. */
static int bdc_data_tx(const uint8_t *eth_hdr, uint32_t hdr_len,
                       const uint8_t *payload, uint32_t pay_len)
{
    uint32_t dlen  = hdr_len + pay_len;
    uint32_t total = 12U + 4U + dlen;

    if (payload == NULL || dlen < 14U || total > CYW43_IOBUF_SZ) {
        return -1;
    }
    /* Respect the firmware TX window: if no credit, drop (the IP stack
     * retransmits). Sending past the window is silently discarded by the
     * firmware and eventually stalls the link. */
    if (!sdpcm_tx_ready()) {
        return -1;
    }
    memset(g_iobuf, 0, (total + 3U) & ~3U);
    sdpcm_hdr(g_iobuf, SDPCM_CHAN_DATA, total);
    /* BDC header (version 2; priority/ifidx/data_offset all 0). */
    g_iobuf[12] = BDC_FLAG_VER;
    if (hdr_len != 0U) {
        memcpy(&g_iobuf[16], eth_hdr, hdr_len);
    }
    memcpy(&g_iobuf[16 + hdr_len], payload, pay_len);
    /* ethertype lives at offset 12 of whichever buffer actually holds >= 14
     * bytes; guard the payload fallback so a partial synthetic header cannot
     * index past a short payload. */
    BRINGUP_LOG("  [tx] %lu bytes ethertype=0x%02X%02X\n",
                (unsigned long)(hdr_len + pay_len),
                (hdr_len >= 14U) ? eth_hdr[12]
                                 : ((pay_len >= 14U) ? payload[12] : 0U),
                (hdr_len >= 14U) ? eth_hdr[13]
                                 : ((pay_len >= 14U) ? payload[13] : 0U));
    f2_write(g_iobuf, total);
    return 0;
}

/* Decode one async event frame and update assoc state. ev points at the
 * BDC header; the Ethernet event frame follows it. */
static void cyw43_handle_event(const uint8_t *ev, uint32_t len)
{
    uint32_t bdc_off, etype, estatus;
    uint16_t eflags;
    const uint8_t *e;

    if (len < 4U) {
        return;
    }
    /* Ethernet event frame = BDC(4) + data_offset*4; wl_event_msg sits
     * 14 (Ethernet) + 10 (bcmeth) = 24 bytes into it. Big-endian fields:
     * flags@26, event_type@28, status@32, source addr@48. */
    bdc_off = 4U + ((uint32_t)ev[3] << 2);
    if (len < bdc_off + 54U) {
        return;
    }
    e = ev + bdc_off;
    eflags  = (uint16_t)(((uint16_t)e[26] << 8) | e[27]);
    etype   = ((uint32_t)e[28] << 24) | ((uint32_t)e[29] << 16)
            | ((uint32_t)e[30] << 8) | (uint32_t)e[31];
    estatus = ((uint32_t)e[32] << 24) | ((uint32_t)e[33] << 16)
            | ((uint32_t)e[34] << 8) | (uint32_t)e[35];

    BRINGUP_LOG("  [ev] type=%lu status=%lu flags=0x%04X\n",
                (unsigned long)etype, (unsigned long)estatus,
                (unsigned)eflags);

    switch (etype) {
    case WLC_E_LINK:
        if ((eflags & WLC_EVENT_MSG_LINK) != 0U) {
            memcpy(g_cyw43.bssid, &e[48], 6);
            g_cyw43.assoc_up = 1;
            g_cyw43.assoc_seen = 1;
        }
        else {
            g_cyw43.assoc_up = 0;
            g_cyw43.keyed = 0;
        }
        break;
    case WLC_E_ASSOC:
        /* ASSOC-success means the 802.11 association completed, but on a
         * WPA2 BSS the port is still UNKEYED here - data sent now is
         * dropped. Track it as link-up for diagnostics, but gate "ready
         * for data" on WLC_E_PSK_SUP (keyed) below, not on this. */
        if (estatus == WLC_E_STATUS_SUCCESS) {
            memcpy(g_cyw43.bssid, &e[48], 6);
            g_cyw43.assoc_up = 1;
            g_cyw43.assoc_seen = 1;
        }
        break;
    case WLC_E_PSK_SUP:
        /* Firmware 4-way supplicant state. KEYED = handshake complete and
         * the link is encrypted: this is the real "join succeeded" signal.
         * Non-keyed boots associate but this never reaches KEYED. */
        if (estatus == WLC_SUP_KEYED) {
            g_cyw43.keyed = 1;
        }
        break;
    case WLC_E_DEAUTH:
    case WLC_E_DEAUTH_IND:
    case WLC_E_DISASSOC:
    case WLC_E_DISASSOC_IND:
        g_cyw43.assoc_up = 0;
        g_cyw43.keyed = 0;
        break;
    default:
        break;
    }
}

int cyw43_connect(const uint8_t *ssid, size_t ssid_len,
                  const uint8_t bssid[6], int channel, int open_auth)
{
    uint8_t  mask[4U + WL_EVENTING_MASK_LEN];
    uint8_t  ssidbuf[WLC_SSID_STRUCT_SZ];
    uint32_t i;
    int      rc;

    (void)channel;
    if (ssid == NULL || ssid_len == 0U || ssid_len > 32U || !g_cyw43.ready) {
        return -1;
    }

    /* Remember the BSSID for EAPOL framing; 0 means learn it from the
     * assoc event source address. */
    if (bssid != NULL) {
        memcpy(g_cyw43.bssid, bssid, 6);
    }
    else {
        memset(g_cyw43.bssid, 0, 6);
    }
    g_cyw43.assoc_up = 0;
    g_cyw43.assoc_seen = 0;
    g_cyw43.keyed = 0;

    /* The host runs the 4-way: disable the firmware's own supplicant. */
    (void)set_iovar_u32("sup_wpa", 0U);

    /* Subscribe to assoc/link/eapol events. The bsscfg:event_msgs value
     * is a 4-byte interface index (0) followed by a 16-byte event mask;
     * event index n sets bit (n & 7) of mask byte (n >> 3). */
    memset(mask, 0, sizeof(mask));
    for (i = 0; i < (uint32_t)sizeof(cyw43_event_subs); i++) {
        mask[4U + (cyw43_event_subs[i] >> 3)] |=
            (uint8_t)(1U << (cyw43_event_subs[i] & 7U));
    }
    (void)set_iovar("bsscfg:event_msgs", mask, sizeof(mask));

    /* Infrastructure, open 802.11 auth (RSN runs above it). */
    (void)cyw43_ioctl_set_u32(WLC_SET_INFRA, INFRA_INFRASTRUCTURE);
    (void)cyw43_ioctl_set_u32(WLC_SET_AUTH, AUTH_OPEN);

    if (open_auth) {
        /* Truly open network: no encryption, no RSN. */
        (void)cyw43_ioctl_set_u32(WLC_SET_WSEC, WSEC_NONE);
        (void)cyw43_ioctl_set_u32(WLC_SET_WPA_AUTH, WPA_AUTH_DISABLED);
    }
    else {
        /* WPA2-PSK / CCMP with the host supplicant doing the 4-way. */
        (void)cyw43_ioctl_set_u32(WLC_SET_WSEC, WSEC_AES_ENABLED);
        (void)cyw43_ioctl_set_u32(WLC_SET_WPA_AUTH, WPA2_AUTH_PSK);
        (void)set_iovar("wpaie", cyw43_rsn_ie_wpa2_psk,
                        (uint32_t)sizeof(cyw43_rsn_ie_wpa2_psk));
    }

    /* Kick off auth + assoc. WLC_SET_SSID payload = wlc_ssid_t. */
    memset(ssidbuf, 0, sizeof(ssidbuf));
    wr32le(&ssidbuf[0], (uint32_t)ssid_len);
    memcpy(&ssidbuf[4], ssid, ssid_len);
    rc = cyw43_ioctl(WLC_SET_SSID, 1, ssidbuf, sizeof(ssidbuf));
    return rc;
}

int cyw43_join_psk(const uint8_t *ssid, size_t ssid_len,
                   const char *passphrase, size_t pass_len)
{
    uint8_t  mask[4U + WL_EVENTING_MASK_LEN];
    uint8_t  pmk[4U + 64U];      /* wsec_pmk_t: key_len(2) flags(2) key[64] */
    uint8_t  ssidbuf[WLC_SSID_STRUCT_SZ];
    uint8_t  cfgval[8];          /* bsscfg iovar: index(4) + value(4)       */
    uint32_t i;
    int      rc;

    if (ssid == NULL || ssid_len == 0U || ssid_len > 32U
        || passphrase == NULL || pass_len == 0U || pass_len > 63U
        || !g_cyw43.ready) {
        return -1;
    }
    memset(g_cyw43.bssid, 0, 6);
    g_cyw43.assoc_up = 0;
    g_cyw43.assoc_seen = 0;
    g_cyw43.keyed = 0;

    /* Take the MAC down before (re)configuring. A fresh interface is
     * already up from cyw43_wifi_up, but on a retry after a non-keyed
     * association the firmware's bsscfg/supplicant state is left wedged - a
     * bare WLC_DISASSOC does not clear it, so every config ioctl then
     * returns BCME_ERROR(-1). WLC_DOWN resets that state; we WLC_UP again
     * just before WLC_SET_SSID. (Ref: cyw43-driver/brcmfmac config is done
     * around an up/down cycle; DISASSOC alone is insufficient.) */
    rc = cyw43_ioctl(WLC_DOWN, 1, 0, 0U);
    BRINGUP_LOG("  [io] down rc=%d\n", rc);

    /* Subscribe to assoc/link/PSK-supplicant events. */
    memset(mask, 0, sizeof(mask));
    for (i = 0; i < (uint32_t)sizeof(cyw43_event_subs); i++) {
        mask[4U + (cyw43_event_subs[i] >> 3)] |=
            (uint8_t)(1U << (cyw43_event_subs[i] & 7U));
    }
    rc = set_iovar("bsscfg:event_msgs", mask, sizeof(mask));
    BRINGUP_LOG("  [io] event_msgs rc=%d\n", rc);

    /* Firmware-offload WPA2-PSK/CCMP: the CYW43439 firmware runs the 4-way
     * itself (host-run PSK is not supported on this FullMAC firmware). We
     * enable the firmware supplicant and push the passphrase; the firmware
     * derives the PMK (PBKDF2) and completes the handshake. */
    rc = cyw43_ioctl_set_u32(WLC_SET_WSEC, WSEC_AES_ENABLED);
    BRINGUP_LOG("  [io] wsec rc=%d\n", rc);

    /* Enable the firmware supplicant. cyw43-driver sets BOTH forms: the
     * bsscfg-prefixed one (4-byte index + value) is what the per-interface
     * 4-way actually keys off. These bsscfg sets are APPLIED by the
     * firmware even though it returns no timely CDC response (they appear
     * to "time out"); without them the link associates but never keys. */
    wr32le(&cfgval[0], 0U);              /* bsscfg index 0 (STA)            */
    wr32le(&cfgval[4], 1U);              /* sup_wpa = 1                     */
    rc = set_iovar("bsscfg:sup_wpa", cfgval, sizeof(cfgval));
    BRINGUP_LOG("  [io] bsscfg:sup_wpa rc=%d\n", rc);
    rc = set_iovar_u32("sup_wpa", 1U);
    BRINGUP_LOG("  [io] sup_wpa rc=%d\n", rc);
    wr32le(&cfgval[4], 0xFFFFFFFFU);     /* sup_wpa2_eapver = -1            */
    (void)set_iovar("bsscfg:sup_wpa2_eapver", cfgval, sizeof(cfgval));
    wr32le(&cfgval[4], 5000U);           /* sup_wpa_tmo = 5000 ms (cyw43)   */
    (void)set_iovar("bsscfg:sup_wpa_tmo", cfgval, sizeof(cfgval));             /* ms */

    busy_loop(50000U);                   /* brief settle (cyw43 waits ~2 ms) */
    memset(pmk, 0, sizeof(pmk));
    pmk[0] = (uint8_t)pass_len;          /* key_len (LE u16)                */
    pmk[1] = (uint8_t)(pass_len >> 8);
    pmk[2] = (uint8_t)WSEC_PASSPHRASE;   /* flags (LE u16) = passphrase     */
    memcpy(&pmk[4], passphrase, pass_len);
    rc = cyw43_ioctl(WLC_SET_WSEC_PMK, 1, pmk, sizeof(pmk));
    /* cyw43_ioctl left the cleartext passphrase in the static g_iobuf; scrub
     * it now rather than waiting for the next ioctl to overwrite it. */
    cyw43_secure_zero(g_iobuf, sizeof(g_iobuf));
    BRINGUP_LOG("  [io] set_pmk rc=%d\n", rc);

    rc = cyw43_ioctl_set_u32(WLC_SET_INFRA, INFRA_INFRASTRUCTURE);
    BRINGUP_LOG("  [io] infra rc=%d\n", rc);
    rc = cyw43_ioctl_set_u32(WLC_SET_AUTH, AUTH_OPEN);
    BRINGUP_LOG("  [io] auth rc=%d\n", rc);
    rc = set_iovar_u32("mfp", 1U);       /* MFP_CAPABLE (cyw43 sets this)   */
    BRINGUP_LOG("  [io] mfp rc=%d\n", rc);
    rc = cyw43_ioctl_set_u32(WLC_SET_WPA_AUTH, WPA2_AUTH_PSK);
    BRINGUP_LOG("  [io] wpa_auth rc=%d\n", rc);

    /* Bring the MAC back up, then let the firmware register the config
     * before association. WLC_SET_SSID triggers the join, so the brief
     * settle here gives the in-firmware supplicant time to latch the PMK -
     * cutting the associate-but-never-key race seen on some boots. */
    rc = cyw43_ioctl(WLC_UP, 1, 0, 0U);
    BRINGUP_LOG("  [io] up rc=%d\n", rc);
    busy_loop(60000U);                   /* ~20 ms settle before SET_SSID    */

    memset(ssidbuf, 0, sizeof(ssidbuf));
    wr32le(&ssidbuf[0], (uint32_t)ssid_len);
    memcpy(&ssidbuf[4], ssid, ssid_len);
    rc = cyw43_ioctl(WLC_SET_SSID, 1, ssidbuf, sizeof(ssidbuf));
    BRINGUP_LOG("  [io] set_ssid rc=%d\n", rc);
    /* Scrub the cleartext passphrase copy (compiler-resistant). */
    cyw43_secure_zero(pmk, sizeof(pmk));
    return rc;
}

int cyw43_disconnect(void)
{
    g_cyw43.assoc_up = 0;
    g_cyw43.keyed = 0;
    return cyw43_ioctl(WLC_DISASSOC, 1, 0, 0U);
}

int cyw43_tx_eapol(const uint8_t *frame, size_t len)
{
    uint8_t hdr[14];

    if (!g_cyw43.ready || frame == NULL) {
        return -1;
    }
    /* Synthesise the 802.3 header: dst = AP, src = STA, type 0x888E. */
    memcpy(&hdr[0], g_cyw43.bssid, 6);
    memcpy(&hdr[6], g_cyw43.mac,   6);
    hdr[12] = (uint8_t)(ETHERTYPE_EAPOL >> 8);
    hdr[13] = (uint8_t)(ETHERTYPE_EAPOL & 0xFFU);
    return bdc_data_tx(hdr, sizeof(hdr), frame, (uint32_t)len);
}

int cyw43_tx_eth(const uint8_t *frame, size_t len)
{
    if (!g_cyw43.ready) {
        return -1;
    }
    /* frame already carries a full Ethernet header. */
    return bdc_data_tx(NULL, 0U, frame, (uint32_t)len);
}

int cyw43_set_key(int kt, uint8_t key_idx, const uint8_t *key, size_t key_len)
{
    int rc;
    if (!g_cyw43.ready || key == NULL || key_len > 32U) {
        return -1;
    }
    memset(g_keybuf, 0, sizeof(g_keybuf));
    wr32le(&g_keybuf[WSEC_KEY_OFF_INDEX], (uint32_t)key_idx);
    wr32le(&g_keybuf[WSEC_KEY_OFF_LEN],   (uint32_t)key_len);
    memcpy(&g_keybuf[WSEC_KEY_OFF_DATA], key, key_len);
    wr32le(&g_keybuf[WSEC_KEY_OFF_ALGO], CRYPTO_ALGO_AES_CCM);
    if (kt == 0) {
        /* Pairwise: primary key, bound to the AP MAC. Refuse to install
         * against a stale/zero BSSID (assoc event missed or bssid was NULL) -
         * the firmware would mis-bind the key to an all-zero address. */
        static const uint8_t zero_mac[6] = { 0, 0, 0, 0, 0, 0 };
        if (!g_cyw43.assoc_seen
            || memcmp(g_cyw43.bssid, zero_mac, 6) == 0) {
            cyw43_secure_zero(g_keybuf, sizeof(g_keybuf));
            return -1;
        }
        wr32le(&g_keybuf[WSEC_KEY_OFF_FLAGS], WL_PRIMARY_KEY);
        memcpy(&g_keybuf[WSEC_KEY_OFF_EA], g_cyw43.bssid, 6);
    }
    /* Group: flags 0, ea = 00:00:00:00:00:00 (already zeroed). */
    rc = cyw43_ioctl(WLC_SET_KEY, 1, g_keybuf, sizeof(g_keybuf));
    /* Scrub the installed temporal key from both static buffers (cyw43_ioctl
     * copied it into g_iobuf), mirroring cyw43_join_psk's passphrase scrub. */
    cyw43_secure_zero(g_keybuf, sizeof(g_keybuf));
    cyw43_secure_zero(g_iobuf,  sizeof(g_iobuf));
    return rc;
}

int cyw43_poll(void)
{
    uint32_t st, rlen, size, doff, paylen;
    uint8_t  chan, hlen;
    uint16_t etype;
    const uint8_t *pay;
    int processed = 0;

    if (!g_cyw43.ready) {
        return 0;
    }

    /* Clear any latched FIFO error first - it gates F2 RX, so an unacked
     * overflow from a prior burst would otherwise keep this poll seeing
     * "no packet" forever (RX stall). */
    gspi_service_irq();

    for (;;) {
        st = gspi_reg_read(GSPI_FUNC_BUS, SPI_STATUS_REGISTER, 0U);
        if (st == 0xFFFFFFFFU || (st & STATUS_F2_PKT_AVAILABLE) == 0U) {
            break;
        }
        rlen = (st & STATUS_F2_PKT_LEN_MASK) >> STATUS_F2_PKT_LEN_SHIFT;
        /* The 4-byte-padded read must fit g_iobuf; reject and abort drain. */
        if (!cyw43_sdpcm_rlen_ok(rlen, CYW43_IOBUF_SZ)) {
            gspi_reg_write(GSPI_FUNC_BACKPLANE, SPI_FRAME_CONTROL, 1U, 1U);
            break;
        }
        f2_read(g_iobuf, rlen);
        /* Validate the SDPCM checksum + declared-vs-actual size. A corrupt
         * frame is already drained by f2_read, so skip it (continue) and keep
         * draining the queued good frames behind it rather than abandon the
         * loop (cf. the matching guards in cyw43_ioctl). */
        if (cyw43_sdpcm_validate(g_iobuf, rlen, &size, &chan) != CYW43_RX_OK) {
            continue;
        }
        sdpcm_update_credit(g_iobuf);     /* refresh TX window from RX */
        hlen = g_iobuf[7];
        if (!cyw43_sdpcm_hlen_ok(hlen, size)) {
            continue;
        }
        processed++;

        if (chan == SDPCM_CHAN_EVENT) {
            cyw43_handle_event(&g_iobuf[hlen], size - hlen);
        }
        else if (chan == SDPCM_CHAN_DATA) {
            /* Validate the BDC data_offset and extract the 802.3 payload
             * (doff becomes the absolute payload offset into g_iobuf). */
            if (cyw43_sdpcm_bdc_payload(g_iobuf, hlen, size,
                                        &doff, &paylen, &etype) != 0) {
                continue;
            }
            pay = &g_iobuf[doff];
            g_cyw43.rx_count++;       /* any inbound data frame = liveness */
            if (etype < 0x0600U) {
                /* 802.3-length / non-Ethernet-II noise (this AP floods
                 * 64-byte type-0x0000 frames). Count for liveness but
                 * drop it - delivering would bury real packets, and the
                 * single-slot wifi.c stage means one per poll. */
                continue;
            }
            BRINGUP_LOG("  [data] ethertype=0x%04X len=%lu\n",
                        (unsigned)etype, (unsigned long)paylen);
            /* The wifi.c RX path stages a SINGLE frame for wolfIP, and both
             * callbacks stage into that same slot. So deliver one frame per
             * poll and return - draining more (EAPOL or data) would overwrite
             * the just-staged frame before wolfIP_poll reads it. */
            if (etype == ETHERTYPE_EAPOL) {
                if (g_cyw43.eapol_cb != NULL) {
                    (void)g_cyw43.eapol_cb(g_cyw43.cb_ctx,
                                           &pay[14], paylen - 14U);
                }
            }
            else if (g_cyw43.data_cb != NULL) {
                (void)g_cyw43.data_cb(g_cyw43.cb_ctx, pay, paylen);
            }
            /* One data frame per poll regardless of whether a callback was
             * registered: the wifi.c RX stage holds a single frame, so
             * draining further frames here would overwrite it. Returning
             * also keeps the "one frame per poll" invariant when a callback
             * is NULL (e.g. before both are registered). */
            return processed;
        }
        /* SDPCM_CHAN_CONTROL here = a stray ioctl response; ignore. */
    }
    return processed;
}

int cyw43_assoc_up(void)
{
    return g_cyw43.assoc_up;
}

/* Diagnostic snapshot of the gSPI RX gates: the F0 status word (0x08, F2
 * packet-available bit 0x100 + length [19:9]) and the latched interrupt
 * register (0x04). Lets the heartbeat distinguish a chip-gated F2 (status
 * shows no packet) from a host that is not draining a flagged packet, and
 * surfaces any stuck error bits. */
void cyw43_rx_diag(uint32_t *status, uint32_t *intr)
{
    if (status != NULL) {
        *status = gspi_reg_read(GSPI_FUNC_BUS, SPI_STATUS_REGISTER, 0U);
    }
    if (intr != NULL) {
        *intr = gspi_reg_read(GSPI_FUNC_BUS, SPI_INTERRUPT_REGISTER, 0U)
                & 0xFFFFU;
    }
}

int cyw43_keyed(void)
{
    return g_cyw43.keyed;
}

int cyw43_get_mac(uint8_t out[6])
{
    if (out == NULL) return -1;
    memcpy(out, g_cyw43.mac, 6);
    return g_cyw43.ready ? 0 : -1;
}

int cyw43_get_bssid(uint8_t out[6])
{
    if (out == NULL) return -1;
    memcpy(out, g_cyw43.bssid, 6);
    /* Valid once the link has come up at least once (the BSSID is latched
     * even if the link then flaps down before the 4-way completes). */
    return g_cyw43.assoc_seen ? 0 : -1;
}

int cyw43_assoc_seen(void)
{
    return g_cyw43.assoc_seen;
}

uint32_t cyw43_rx_count(void)
{
    return g_cyw43.rx_count;
}
