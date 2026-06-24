/* cyw43439_driver.h - clean-room CYW43439 firmware loader + ioctl shim
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
 * Surface contract:
 *
 *   cyw43_init()      = power up, gSPI handshake, load firmware blob
 *                       and CLM regional blob, bring the ARM up,
 *                       handshake with the running firmware.
 *
 *   cyw43_wifi_up()   = WLC_UP ioctl + country code + EAPOL/event
 *                       channel registration.
 *
 *   cyw43_connect()   = WLC_SET_SSID + SET_KEY plumbing for an open or
 *                       pre-shared assoc; the WPA{2,3} 4-way / SAE
 *                       handshake itself runs in the wolfIP supplicant
 *                       and we just shuttle EAPOL frames in/out.
 *
 *   cyw43_tx_eapol()  = push one EAPOL frame onto the F2 data channel
 *                       (BDC encapsulation, type 0x888E).
 *
 *   cyw43_poll()      = service inbound F2 traffic, dispatch EAPOL to
 *                       the supplicant and 802.3 frames to wolfIP.
 *
 *   cyw43_set_key()   = WLC_SET_KEY ioctl. Called by the supplicant
 *                       through the wolfIP_wifi_ops vtable to install
 *                       PTK / GTK once the handshake completes.
 */

#ifndef WOLFIP_CYW43439_DRIVER_H
#define WOLFIP_CYW43439_DRIVER_H

#include <stdint.h>
#include <stddef.h>

/* Bring-up diagnostics master switch. Default OFF: the demo prints only
 * the high-level banner, join result, DHCP lease and heartbeat. Build with
 * DEBUG_BRINGUP=1 (e.g. EXTRA_CFLAGS=-DDEBUG_BRINGUP=1) to compile in the
 * verbose gSPI / firmware / ioctl / event / credit progress logging when
 * debugging the data path on hardware. */
#ifndef DEBUG_BRINGUP
#define DEBUG_BRINGUP 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bring the radio up: power, gSPI handshake, firmware load, ARM start,
 * firmware-handshake. Returns 0 on success. */
int cyw43_init(void);

/* WLC_UP + country code + register host for EAPOL events. country is
 * a 2-char ISO 3166-1 alpha-2 code ("US", "GB", ...). NULL = "XX"
 * (worldwide regulatory subset). */
int cyw43_wifi_up(const char *country);

/* Set firmware power-management mode (WLC_SET_PM): 0 = CAM / constantly
 * awake (no sleep). Must be applied AFTER association - firmware resets PM
 * on each (re)join. Keeps inbound frames flowing continuously instead of
 * trickling through erratically (which presents as an intermittent RX
 * stall). Returns the ioctl result. */
int cyw43_set_powersave(uint32_t pm);

/* Initiate association to the named SSID. open_auth = 1 for an open
 * (non-RSN) network; for WPA2/WPA3 the call kicks off MLME and the
 * 4-way / SAE handshake runs in the wolfIP supplicant. Returns 0 once
 * the (Re)Assoc Response arrives with a success code; the supplicant
 * is responsible for finishing the handshake before traffic flows.
 *
 * bssid may be NULL (any matching SSID). channel = 0 means scan all. */
int cyw43_connect(const uint8_t *ssid, size_t ssid_len,
                  const uint8_t bssid[6], int channel,
                  int open_auth);

/* Firmware-offload WPA2-PSK join. The CYW43439 firmware runs the 4-way
 * handshake itself (host-run PSK is not supported on this FullMAC
 * firmware), so the passphrase is pushed to the firmware which derives
 * the PMK and authenticates. Watch cyw43_assoc_up() / WLC_E_PSK_SUP for
 * completion. Returns 0 once the join is issued. */
int cyw43_join_psk(const uint8_t *ssid, size_t ssid_len,
                   const char *passphrase, size_t pass_len);

/* Tear down the association. */
int cyw43_disconnect(void);

/* Push one outbound EAPOL frame (ethertype 0x888E payload, no MAC
 * header) into the radio. Returns 0 on success. */
int cyw43_tx_eapol(const uint8_t *frame, size_t len);

/* Push one outbound 802.3 frame (full Ethernet, dst-MAC + src-MAC +
 * ethertype + payload). The radio strips the dst-MAC for 802.11 TX. */
int cyw43_tx_eth(const uint8_t *frame, size_t len);

/* Install a session key. kt = 0 (pairwise) or 1 (group). key_idx is
 * the 802.11 key ID (0..3). */
int cyw43_set_key(int kt, uint8_t key_idx,
                  const uint8_t *key, size_t key_len);

/* Drain any pending RX traffic from the radio and dispatch:
 *   - EAPOL  -> eapol_rx_cb(ctx, frame, len)
 *   - 802.3  -> data_rx_cb (ctx, frame, len)
 *   - events -> internal handling (assoc up/down, BSSID change, ...)
 *
 * Returns the number of frames processed. */
typedef int (*cyw43_eapol_cb_t)(void *ctx, const uint8_t *frame, size_t len);
typedef int (*cyw43_data_cb_t) (void *ctx, const uint8_t *frame, size_t len);

void cyw43_set_rx_callbacks(cyw43_eapol_cb_t eapol_cb,
                            cyw43_data_cb_t  data_cb,
                            void *ctx);

int  cyw43_poll(void);

/* Read the radio's permanent MAC address (set during firmware load
 * from OTP). out is 6 bytes. Returns 0 on success. */
int  cyw43_get_mac(uint8_t out[6]);

/* Read the associated AP's BSSID (learned during assoc). out is 6
 * bytes. Returns 0 once associated, -1 before assoc. The supplicant
 * needs this as the authenticator address for PTK derivation. */
int  cyw43_get_bssid(uint8_t out[6]);

/* gSPI test-register (F0 0x14) reads captured during cyw43_init(), for
 * bring-up diagnostics over UART. 0xFEEDBEAD means the link is good.
 *   _pre  : read in the initial post-reset 16-bit-swapped mode
 *   (plain): read after switching the bus to 32-bit big-endian mode
 */
uint32_t cyw43_last_bus_test(void);
uint32_t cyw43_last_bus_test_pre(void);
/* ChipCommon chip id read over the backplane (0xA9A6 = 43439) and ALP
 * clock status, for bring-up diagnostics. */
uint32_t cyw43_last_chip_id(void);
int      cyw43_last_alp_ok(void);
uint32_t cyw43_last_alp_csr(void);
/* 1 once firmware is downloaded and the F2 data channel is ready. */
int      cyw43_firmware_ready(void);

/* 1 once the radio has reported link/assoc up (updated by cyw43_poll
 * from the async WLC_E_LINK / WLC_E_SET_SSID events). The integrator
 * watches this to kick the wolfIP supplicant's 4-way handshake. */
int      cyw43_assoc_up(void);

/* 1 once the firmware's WPA2-PSK 4-way handshake has fully completed
 * (WLC_E_PSK_SUP / WLC_SUP_KEYED). This - not cyw43_assoc_up() - is the
 * trigger to start DHCP: on a secured BSS the link associates (assoc_up)
 * well before it keys, and a non-keyed boot never reaches this. Cleared on
 * a new join and on link loss (deauth/disassoc/link-down). */
int      cyw43_keyed(void);

/* Diagnostic: read the gSPI F2 RX gates - F0 status word (0x08) and the
 * latched interrupt register (0x04). Used by the demo heartbeat to probe an
 * RX stall. Either pointer may be NULL. */
void     cyw43_rx_diag(uint32_t *status, uint32_t *intr);

/* 1 once the link has come up at least once since the last connect. The
 * link can flap (the AP deauths while the host 4-way is pending), so the
 * supplicant keys off this latched signal rather than the live assoc_up
 * to capture the BSSID and start the handshake. Cleared by cyw43_connect. */
int      cyw43_assoc_seen(void);

/* Count of inbound data frames seen (any ethertype, incl. broadcast
 * noise). A stalled count while associated means the link silently
 * dropped - the demo uses it to trigger a re-join. */
uint32_t cyw43_rx_count(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_CYW43439_DRIVER_H */
