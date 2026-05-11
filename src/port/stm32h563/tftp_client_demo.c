/* tftp_client_demo.c
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
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Wires the wolfIP TFTP client into the STM32H5 demo. Performs a
 * one-shot RRQ GET of a host-served firmware image and stages the
 * bytes into the wolfBoot update partition at
 * WOLFBOOT_PARTITION_UPDATE_ADDRESS. On successful verify the demo
 * sets the wolfBoot update flag in the swap trailer so wolfBoot picks
 * the staged image up on the next reset.
 *
 * TZEN=0 only: writes flash directly via the non-secure FLASH register
 * view. The TZEN=1 path is intentionally out of scope here.
 */

#include "wolfip.h"
#include "wolftftp.h"
#include "tftp_client_demo.h"

#include <stdint.h>
#include <string.h>
#include <limits.h>

/* ----- wolfBoot partition layout (override via -D in Makefile) ------ */
#ifndef WOLFBOOT_PARTITION_UPDATE_ADDRESS
#define WOLFBOOT_PARTITION_UPDATE_ADDRESS 0x08100000UL
#endif
#ifndef WOLFBOOT_PARTITION_SIZE
#define WOLFBOOT_PARTITION_SIZE 0xA0000UL
#endif
#ifndef WOLFBOOT_SECTOR_SIZE
#define WOLFBOOT_SECTOR_SIZE 0x4000UL
#endif

/* IMG_STATE_UPDATING from wolfBoot. Written to the very last byte of
 * the update partition trailer to ask wolfBoot to swap on next boot.
 * Using the non-inverted-flags convention (matches stm32h5-no-tz). */
#ifndef WOLFBOOT_IMG_STATE_UPDATING
#define WOLFBOOT_IMG_STATE_UPDATING 0x70U
#endif

/* ----- STM32H5 FLASH controller (TZEN=0 / non-secure view) ---------- */
/* Offsets match wolfBoot/hal/stm32h5.h FLASH_NS_* but redeclared here
 * to keep this demo independent of the wolfBoot tree. */
#define H5_FLASH_BASE         0x40022000UL
#define H5_FLASH_KEYR         (*(volatile uint32_t *)(H5_FLASH_BASE + 0x04))
#define H5_FLASH_SR           (*(volatile uint32_t *)(H5_FLASH_BASE + 0x20))
#define H5_FLASH_CR           (*(volatile uint32_t *)(H5_FLASH_BASE + 0x28))
#define H5_FLASH_CCR          (*(volatile uint32_t *)(H5_FLASH_BASE + 0x30))
#define H5_FLASH_OPTSR_CUR    (*(volatile uint32_t *)(H5_FLASH_BASE + 0x50))

#define H5_FLASH_KEY1         0x45670123UL
#define H5_FLASH_KEY2         0xCDEF89ABUL

#define H5_FLASH_CR_LOCK      (1U << 0)
#define H5_FLASH_CR_PG        (1U << 1)
#define H5_FLASH_CR_SER       (1U << 2)
#define H5_FLASH_CR_BER       (1U << 3)
#define H5_FLASH_CR_STRT      (1U << 5)
#define H5_FLASH_CR_PNB_SHIFT 6
#define H5_FLASH_CR_PNB_MASK  0x7FU
#define H5_FLASH_CR_MER       (1U << 15)
#define H5_FLASH_CR_BKSEL     (1U << 31)

#define H5_FLASH_SR_BSY       (1U << 0)
#define H5_FLASH_SR_EOP       (1U << 16)

/* FLASH_CCR is write-1-clear for all the status/error bits we care
 * about: clear EOP, all error flags, and the BSY clear bits. */
#define H5_FLASH_CCR_CLR_ALL  (0x7FE0001FU)

/* Any SR error flag: bits 17-26 (WRPERR, PGSERR, STRBERR, INCERR,
 * OBKERR, OBKWERR, OPTCHANGEERR, etc. per H5 RM). */
#define H5_FLASH_SR_ERR_MASK  (0x07FE0000U)

#define H5_FLASH_OPTSR_SWAP_BANK (1U << 31)

#define H5_FLASH_PAGE_SIZE    0x2000UL  /* 8KB erase granule */
#define H5_FLASH_BANK2_BASE   0x08100000UL
#define H5_FLASH_TOP          0x081FFFFFUL
#define H5_FLASH_BASE_ADDR    0x08000000UL

/* ----- TFTP tunables ---------------------------------------------- */
#define TFTP_CLIENT_LOCAL_PORT 20100U
#define TFTP_DEMO_BLKSIZE      1428U
#define TFTP_DEMO_WINDOWSIZE   8U
#define TFTP_DEMO_TIMEOUT_S    1U
#define TFTP_DEMO_MAX_RETRIES  5U
#define TFTP_DEMO_RX_BUF       1500U

/* ----- Module state (single-shot, single transfer) ----------------- */
struct tftp_demo_handle {
    uint32_t bytes_written;
    uint32_t erased_through;   /* address >=erased_through is fresh-erased */
    uint32_t qword_addr;       /* flash address of the qword being filled */
    uint8_t  qword[16];
    uint8_t  qword_have;
    uint8_t  flash_unlocked;
};

static struct wolfIP *g_stack;
static struct wolftftp_client g_client;
static int g_sock = -1;
static int g_started;
static int g_last_status = INT_MIN;
static uint32_t g_server_ip;
static struct tftp_demo_handle g_handle;
static tftp_client_demo_debug_cb g_dbg;
static uint8_t g_rx_buf[TFTP_DEMO_RX_BUF];

/* ----- Logging helpers --------------------------------------------- */
static void dbg(const char *s)
{
    if (g_dbg != NULL)
        g_dbg(s);
}

static void dbg_u32(const char *prefix, uint32_t v)
{
    char buf[12];
    int i;
    int n = 0;
    if (v == 0) {
        buf[n++] = '0';
    } else {
        char tmp[12];
        int t = 0;
        while (v != 0) {
            tmp[t++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (i = t - 1; i >= 0; i--)
            buf[n++] = tmp[i];
    }
    buf[n] = '\0';
    if (prefix != NULL)
        dbg(prefix);
    dbg(buf);
}

/* Signed-decimal counterpart to dbg_u32(); used for status codes that
 * are negative WOLFTFTP_ERR_* values. */
static void dbg_i32(const char *prefix, int32_t v)
{
    uint32_t u;
    if (v < 0) {
        if (prefix != NULL)
            dbg(prefix);
        dbg("-");
        u = (uint32_t)(-(v + 1)) + 1U;
        dbg_u32(NULL, u);
    } else {
        dbg_u32(prefix, (uint32_t)v);
    }
}

/* ----- Inline H5 flash HAL (TZEN=0) -------------------------------- */
static void h5_flash_wait(void)
{
    while ((H5_FLASH_SR & H5_FLASH_SR_BSY) != 0)
        ;
}

static void h5_flash_clear_errors(void)
{
    H5_FLASH_CCR = H5_FLASH_CCR_CLR_ALL;
}

static void h5_flash_unlock(void)
{
    h5_flash_wait();
    if ((H5_FLASH_CR & H5_FLASH_CR_LOCK) != 0) {
        H5_FLASH_KEYR = H5_FLASH_KEY1;
        H5_FLASH_KEYR = H5_FLASH_KEY2;
        while ((H5_FLASH_CR & H5_FLASH_CR_LOCK) != 0)
            ;
    }
}

static void h5_flash_lock(void)
{
    h5_flash_wait();
    if ((H5_FLASH_CR & H5_FLASH_CR_LOCK) == 0)
        H5_FLASH_CR |= H5_FLASH_CR_LOCK;
}

/* Erase the 8KB page that covers `addr`. addr must be page-aligned. */
static int h5_flash_erase_page(uint32_t addr)
{
    uint32_t reg;
    uint32_t bnksel = 0;
    uint32_t base = H5_FLASH_BASE_ADDR;

    if (addr < H5_FLASH_BASE_ADDR || addr > H5_FLASH_TOP)
        return -1;
    if (addr >= H5_FLASH_BANK2_BASE) {
        base = H5_FLASH_BANK2_BASE;
        bnksel = 1;
    }
    if (((H5_FLASH_OPTSR_CUR & H5_FLASH_OPTSR_SWAP_BANK) >> 31) != 0)
        bnksel = bnksel ? 0 : 1;

    h5_flash_clear_errors();
    reg = H5_FLASH_CR & ~((H5_FLASH_CR_PNB_MASK << H5_FLASH_CR_PNB_SHIFT) |
        H5_FLASH_CR_SER | H5_FLASH_CR_BER | H5_FLASH_CR_PG | H5_FLASH_CR_MER |
        H5_FLASH_CR_BKSEL);
    reg |= (((addr - base) >> 13) << H5_FLASH_CR_PNB_SHIFT) | H5_FLASH_CR_SER |
        (bnksel ? H5_FLASH_CR_BKSEL : 0U);
    H5_FLASH_CR = reg;
    __asm volatile ("isb");
    H5_FLASH_CR |= H5_FLASH_CR_STRT;
    h5_flash_wait();
    H5_FLASH_CR &= ~H5_FLASH_CR_SER;
    if ((H5_FLASH_SR & H5_FLASH_SR_ERR_MASK) != 0) {
        dbg_u32("TFTP: erase SR err=", H5_FLASH_SR & H5_FLASH_SR_ERR_MASK);
        dbg("\n");
        H5_FLASH_CCR = H5_FLASH_CCR_CLR_ALL;
        return -1;
    }
    return 0;
}

/* Program one 128-bit (16-byte) quad-word at addr. addr must be 16-byte
 * aligned. */
static int h5_flash_program_qword(uint32_t addr, const uint8_t *qword)
{
    volatile uint32_t *dst;
    const uint32_t *src;
    int i;
    uint32_t buf[4];

    if ((addr & 0xFU) != 0)
        return -1;
    h5_flash_clear_errors();
    /* Copy into a local aligned buffer; the caller's `qword` may be
     * arbitrarily aligned (it comes out of a TFTP DATA byte stream). */
    for (i = 0; i < 16; i++)
        ((uint8_t *)buf)[i] = qword[i];
    dst = (volatile uint32_t *)addr;
    src = buf;
    H5_FLASH_CR |= H5_FLASH_CR_PG;
    for (i = 0; i < 4; i++) {
        dst[i] = src[i];
        __asm volatile ("isb");
    }
    h5_flash_wait();
    {
        uint32_t sr = H5_FLASH_SR;
        /* Clear EOP / error flags via CCR (FLASH_SR bits are read-only
         * on H5; CCR is write-1-to-clear). */
        H5_FLASH_CCR = H5_FLASH_CCR_CLR_ALL;
        H5_FLASH_CR &= ~H5_FLASH_CR_PG;
        if ((sr & H5_FLASH_SR_ERR_MASK) != 0) {
            dbg_u32("TFTP: program SR err=", sr & H5_FLASH_SR_ERR_MASK);
            dbg("\n");
            return -1;
        }
    }
    return 0;
}

/* ----- TFTP io_ops mapped to the wolfBoot update partition --------- */
static int demo_open(void *arg, const char *name, int is_write,
    uint32_t *size_hint, void **handle)
{
    struct tftp_demo_handle *h = &g_handle;

    (void)arg;
    (void)name;
    (void)size_hint;
    if (!is_write)
        return WOLFTFTP_ERR_UNSUPPORTED;
    h->bytes_written = 0;
    h->erased_through = WOLFBOOT_PARTITION_UPDATE_ADDRESS;
    h->qword_addr = WOLFBOOT_PARTITION_UPDATE_ADDRESS;
    h->qword_have = 0;
    h->flash_unlocked = 0;
    memset(h->qword, 0xFF, sizeof(h->qword));

    h5_flash_unlock();
    h->flash_unlocked = 1;
    *handle = h;
    dbg("TFTP: open update partition (erase on demand)\n");
    return 0;
}

/* Make sure flash from [erased_through .. addr_end) is erased. */
static int demo_ensure_erased(struct tftp_demo_handle *h, uint32_t addr_end)
{
    while (h->erased_through < addr_end) {
        int rc = h5_flash_erase_page(h->erased_through);
        if (rc != 0)
            return rc;
        h->erased_through += H5_FLASH_PAGE_SIZE;
    }
    return 0;
}

/* Flush g_handle.qword to flash if it is full (qword_have == 16). The
 * flash address comes from h->qword_addr, captured when the first byte
 * of this qword was buffered - bytes_written has since advanced past
 * the qword and can't be used here. */
static int demo_flush_qword(struct tftp_demo_handle *h)
{
    int rc;

    if (h->qword_have < 16)
        return 0;
    rc = demo_ensure_erased(h, h->qword_addr + 16U);
    if (rc != 0)
        return rc;
    rc = h5_flash_program_qword(h->qword_addr, h->qword);
    if (rc != 0)
        return rc;
    h->qword_addr += 16U;
    h->qword_have = 0;
    memset(h->qword, 0xFF, sizeof(h->qword));
    return 0;
}

static int demo_write(void *arg, void *handle, uint32_t offset,
    const uint8_t *buf, uint16_t len)
{
    struct tftp_demo_handle *h = (struct tftp_demo_handle *)handle;
    uint16_t i;

    (void)arg;
    (void)offset;
    if (h == NULL || buf == NULL)
        return WOLFTFTP_ERR_IO;
    if ((uint32_t)h->bytes_written + (uint32_t)len > WOLFBOOT_PARTITION_SIZE)
        return WOLFTFTP_ERR_SIZE;
    for (i = 0; i < len; i++) {
        h->qword[h->qword_have++] = buf[i];
        h->bytes_written++;
        if (h->qword_have == 16) {
            int rc = demo_flush_qword(h);
            if (rc != 0) {
                dbg("TFTP: flash program failed\n");
                return WOLFTFTP_ERR_IO;
            }
        }
    }
    return 0;
}

static int demo_hash_update(void *arg, void *handle,
    const uint8_t *buf, uint16_t len)
{
    (void)arg;
    (void)handle;
    (void)buf;
    (void)len;
    /* wolfBoot re-hashes on next boot via its own signature check. */
    return 0;
}

/* Write IMG_STATE_UPDATING to the last byte of the update partition.
 * This is the wolfBoot "trigger" marker used by libwolfboot.c for
 * non-inverted-flags builds (stm32h5-no-tz config). The page that
 * contains the trailer is the last page of the partition; it has
 * already been erased by demo_open() / demo_ensure_erased() once we
 * pass through it on the way to the end, so a single byte write
 * (programmed as a qword with 0xFF padding) is sufficient. */
static int demo_trigger_update(void)
{
    uint32_t trailer_addr;
    uint32_t qword_addr;
    uint32_t off;
    uint8_t qword[16];
    int rc;

    trailer_addr = WOLFBOOT_PARTITION_UPDATE_ADDRESS +
        WOLFBOOT_PARTITION_SIZE - 1U;
    qword_addr = trailer_addr & ~0xFU;
    off = trailer_addr - qword_addr;
    /* Erase the page that holds the trailer (in case bytes_written
     * stopped earlier in the partition and we never erased it). */
    rc = demo_ensure_erased(&g_handle,
        (qword_addr & ~(H5_FLASH_PAGE_SIZE - 1U)) + H5_FLASH_PAGE_SIZE);
    if (rc != 0)
        return rc;
    memset(qword, 0xFF, sizeof(qword));
    qword[off] = WOLFBOOT_IMG_STATE_UPDATING;
    return h5_flash_program_qword(qword_addr, qword);
}

static int demo_verify(void *arg, void *handle, uint32_t total_size)
{
    struct tftp_demo_handle *h = (struct tftp_demo_handle *)handle;
    int rc;

    (void)arg;
    if (h == NULL)
        return WOLFTFTP_ERR_IO;
    /* Pad any trailing partial qword with 0xFF and flush. */
    if (h->qword_have > 0 && h->qword_have < 16) {
        while (h->qword_have < 16)
            h->qword[h->qword_have++] = 0xFFU;
        rc = demo_flush_qword(h);
        if (rc != 0)
            return WOLFTFTP_ERR_IO;
    }
    dbg_u32("TFTP: programmed bytes=", h->bytes_written);
    dbg("\n");
    if (total_size != 0 && total_size != h->bytes_written) {
        dbg("TFTP: byte count mismatch vs tsize\n");
        return WOLFTFTP_ERR_VERIFY;
    }
    rc = demo_trigger_update();
    if (rc != 0) {
        dbg("TFTP: failed to set update flag\n");
        return WOLFTFTP_ERR_IO;
    }
    dbg("TFTP: update flag set, reset to apply\n");
    return 0;
}

static void demo_close(void *arg, void *handle, int status)
{
    struct tftp_demo_handle *h = (struct tftp_demo_handle *)handle;

    (void)arg;
    if (h != NULL && h->flash_unlocked) {
        h5_flash_lock();
        h->flash_unlocked = 0;
    }
    g_last_status = status;
    dbg_i32("TFTP: close status=", status);
    dbg("\n");
}

/* ----- Transport: send via wolfIP UDP socket ----------------------- */
static int demo_udp_send(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct wolfIP_sockaddr_in dst;
    int ret;

    (void)arg;
    (void)local_port;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(remote->port);
    dst.sin_addr.s_addr = ee32(remote->ip);
    ret = wolfIP_sock_sendto(g_stack, g_sock, buf, len, 0,
        (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    if (ret == (int)len)
        return 0;
    return ret < 0 ? ret : -1;
}

/* ----- Public API -------------------------------------------------- */
int tftp_client_demo_start(struct wolfIP *stack, uint32_t server_ip,
    const char *filename, tftp_client_demo_debug_cb debug_cb)
{
    struct wolfIP_sockaddr_in bind_addr;
    struct wolftftp_endpoint server_ep;
    struct wolftftp_transport_ops tx;
    struct wolftftp_io_ops io;
    struct wolftftp_transfer_cfg cfg;
    int ret;

    if (stack == NULL || filename == NULL)
        return -1;
    if (g_started)
        return -1;

    g_stack = stack;
    g_dbg = debug_cb;
    g_server_ip = server_ip;

    g_sock = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    if (g_sock < 0) {
        dbg("TFTP: socket() failed\n");
        return -1;
    }
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(TFTP_CLIENT_LOCAL_PORT);
    bind_addr.sin_addr.s_addr = 0;
    ret = wolfIP_sock_bind(stack, g_sock,
        (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));
    if (ret < 0) {
        dbg("TFTP: bind() failed\n");
        wolfIP_sock_close(stack, g_sock);
        g_sock = -1;
        return -1;
    }

    memset(&tx, 0, sizeof(tx));
    tx.send = demo_udp_send;
    tx.arg = NULL;

    memset(&io, 0, sizeof(io));
    io.open = demo_open;
    io.write = demo_write;
    io.hash_update = demo_hash_update;
    io.verify = demo_verify;
    io.close = demo_close;
    io.arg = NULL;

    memset(&cfg, 0, sizeof(cfg));
    cfg.local_port = TFTP_CLIENT_LOCAL_PORT;
    cfg.blksize = TFTP_DEMO_BLKSIZE;
    cfg.timeout_s = TFTP_DEMO_TIMEOUT_S;
    cfg.windowsize = TFTP_DEMO_WINDOWSIZE;
    cfg.max_retries = TFTP_DEMO_MAX_RETRIES;
    cfg.max_image_size = WOLFBOOT_PARTITION_SIZE;

    wolftftp_client_init(&g_client, &tx, &io, &cfg);

    server_ep.ip = server_ip;
    server_ep.port = WOLFTFTP_PORT;
    ret = wolftftp_client_start_rrq(&g_client, &server_ep, filename);
    if (ret != 0) {
        dbg_i32("TFTP: start_rrq failed rc=", ret);
        dbg("\n");
        wolfIP_sock_close(stack, g_sock);
        g_sock = -1;
        return ret;
    }
    g_started = 1;
    g_last_status = 1; /* in progress */
    dbg("TFTP: RRQ sent\n");
    return 0;
}

void tftp_client_demo_poll(uint32_t now_ms)
{
    struct wolfIP_sockaddr_in remote;
    socklen_t rlen;
    int n;

    if (!g_started || g_sock < 0)
        return;

    for (;;) {
        rlen = sizeof(remote);
        n = wolfIP_sock_recvfrom(g_stack, g_sock, g_rx_buf,
            sizeof(g_rx_buf), 0, (struct wolfIP_sockaddr *)&remote, &rlen);
        if (n <= 0)
            break;
        {
            struct wolftftp_endpoint rep;
            rep.ip = ee32(remote.sin_addr.s_addr);
            rep.port = ee16(remote.sin_port);
            (void)wolftftp_client_receive(&g_client,
                TFTP_CLIENT_LOCAL_PORT, &rep, g_rx_buf, (uint16_t)n);
        }
    }
    (void)wolftftp_client_poll(&g_client, now_ms);

    /* Status semantics exposed via tftp_client_demo_status():
     *   INT_MIN = never started
     *   1       = transfer in progress (set in start())
     *   0       = transfer complete (success)
     *   < 0     = transfer failed with WOLFTFTP_ERR_* (or -1 fallback)
     * Latch the first time the wolftftp state machine reports a terminal
     * state so the user-facing status() stays stable after completion. */
    if (g_last_status == 1) {
        if (g_client.state == WOLFTFTP_CLIENT_COMPLETE) {
            g_last_status = 0;
            dbg("TFTP: transfer complete\n");
        } else if (g_client.state == WOLFTFTP_CLIENT_ERROR) {
            int s = wolftftp_client_status(&g_client);
            g_last_status = s != 0 ? s : -1;
            dbg_i32("TFTP: transfer failed rc=", g_last_status);
            dbg("\n");
        }
    }
}

int tftp_client_demo_status(void)
{
    return g_last_status;
}
