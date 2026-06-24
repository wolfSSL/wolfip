/* nl80211_sta.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Reusable SoftMAC STA radio glue for the wolfIP supplicant.
 *
 * Drives a Linux mac80211 station radio (mac80211_hwsim, or a real
 * SoftMAC USB card such as a TP-Link ath9k_htc / rtl8xxxu / mt76) via
 * nl80211, and wires it to the transport-agnostic wolfip_supplicant ops:
 *
 *   - WPA2-PSK / WPA2-Enterprise:
 *       NL80211_CMD_CONNECT (kernel does open auth + (re)assoc),
 *       CONTROL_PORT so EAPOL flows over AF_PACKET to the supplicant.
 *   - WPA3-SAE:
 *       NL80211_CMD_AUTHENTICATE carrying the SAE Commit / Confirm in
 *       NL80211_ATTR_SAE_DATA (the SoftMAC SAE path mac80211/hwsim
 *       support), then NL80211_CMD_ASSOCIATE once SAE completes.
 *
 * After the 4-way handshake the negotiated PTK / GTK are installed into
 * the kernel via NL80211_CMD_NEW_KEY so encrypted data can flow.
 *
 * This is the STA-side analog of tools/hostapd/nl80211_connect.c (which
 * only did PSK CONNECT) and replaces the FullMAC external-auth transport
 * in src/supplicant/test_supplicant_hostapd_sae.c for SoftMAC radios.
 *
 * Requires libnl-genl-3. Linux only.
 */

#ifndef WOLFIP_NL80211_STA_H
#define WOLFIP_NL80211_STA_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>

#include "supplicant.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AKM / auth method. Selects the nl80211 join path. */
enum nl80211_sta_akm {
    NL80211_STA_AKM_PSK   = 0,  /* WPA2-Personal      (CONNECT, open auth) */
    NL80211_STA_AKM_SAE   = 1,  /* WPA3-Personal      (AUTHENTICATE + SAE) */
    NL80211_STA_AKM_8021X = 2   /* WPA2-Enterprise    (CONNECT, 802.1X)    */
};

/* IEEE 802.11w / Management Frame Protection policy. */
enum nl80211_sta_mfp {
    NL80211_STA_MFP_NONE     = 0,
    NL80211_STA_MFP_CAPABLE  = 1,
    NL80211_STA_MFP_REQUIRED = 2
};

/* Opaque libnl handle. */
struct nl_sock;

struct nl80211_sta {
    char     ifname[IFNAMSIZ];
    int      ifindex;
    uint8_t  sta_mac[6];
    uint8_t  bssid[6];
    uint32_t freq_mhz;
    char     ssid[WOLFIP_SUPPLICANT_MAX_SSID + 1];
    size_t   ssid_len;
    enum nl80211_sta_akm akm;
    enum nl80211_sta_mfp mfp;

    /* RSN IE assembled for the (Re)Assoc Request / CONNECT. */
    uint8_t  rsn_ie[64];
    size_t   rsn_ie_len;

    int             packet_sock;     /* AF_PACKET, ethertype 0x888E (EAPOL) */
    struct nl_sock *nl_cmd;
    struct nl_sock *nl_event;
    struct nl_sock *nl_cport;        /* control-port EAPOL TX/RX (SOCKET_OWNER
                                      * of the association; read only in poll,
                                      * never used for synchronous commands)  */
    int             nl_family;

    struct wolfip_supplicant *supp;  /* attached supplicant (optional)      */

    /* PMKSA fast-reconnect (set via nl80211_sta_set_pmksa): open auth
     * (AUTHENTICATE/OPEN) + ASSOCIATE carrying this PMKID in the RSN IE
     * skips the dragonfly; hostapd matches the cached PMKSA. */
    int      pmksa_reconnect;
    uint8_t  pmkid[16];
    uint8_t  pmk[32];
    size_t   pmk_len;
    int      expect_disconnect;  /* swallow one self-issued DISCONNECT event */

    /* Progress / status flags driven by the event pump. */
    int  started;            /* CONNECT issued, or SAE Commit emitted        */
    int  associated;         /* kernel CONNECT / ASSOCIATE succeeded          */
    int  sae_authenticated;  /* supplicant reached 4WAY_M1_WAIT after SAE     */
    int  assoc_sent;         /* SAE: ASSOCIATE issued                         */
    int  port_authorized;    /* controlled port opened after the 4-way        */
    int  failed;             /* hard failure (disconnect / status != 0)       */
    int  verbose;            /* extra stderr tracing                          */
};

/* Open AF_PACKET (EAPOL) + two genl sockets, resolve the nl80211 family
 * and subscribe to the "mlme" multicast group. Reads the netdev's MAC and
 * ifindex. Returns 0 on success, negative on error. */
int nl80211_sta_init(struct nl80211_sta *st, const char *ifname);

/* Release sockets. Tears the link down (DISCONNECT). */
void nl80211_sta_cleanup(struct nl80211_sta *st);

/* Tear down the current association and clear the per-connection progress
 * flags, keeping the sockets + attached supplicant for a reconnect on the
 * same session (e.g. a PMKSA fast reconnect). */
void nl80211_sta_reset(struct nl80211_sta *st);

/* Set the join target (from scan results) and assemble the RSN IE that
 * matches akm + mfp. Returns 0 on success. */
int nl80211_sta_set_target(struct nl80211_sta *st, const char *ssid,
                           const uint8_t bssid[6], uint32_t freq_mhz,
                           enum nl80211_sta_akm akm, enum nl80211_sta_mfp mfp);

/* Fill a supplicant ops vector wired to this radio (send_eapol,
 * install_key, send_auth_frame); ops->ctx is set to st. */
void nl80211_sta_supplicant_ops(struct nl80211_sta *st,
                                struct wolfip_supplicant_ops *ops);

/* Attach the supplicant so the event pump can feed it RX EAPOL / auth
 * frames and drive the SAE -> ASSOCIATE transition. */
void nl80211_sta_attach(struct nl80211_sta *st,
                        struct wolfip_supplicant *supp);

/* Arm a WPA3-SAE PMKSA fast reconnect with the PMKID + PMK from a prior
 * session and the PMKID-bearing RSN IE (the supplicant's own_rsn_ie after
 * wolfip_supplicant_pmksa_reconnect). nl80211_sta_start then does an open
 * AUTHENTICATE + ASSOCIATE (PMKID in the RSN IE) instead of the SAE
 * AUTHENTICATE exchange. Returns 0 on success. */
int nl80211_sta_set_pmksa(struct nl80211_sta *st,
                          const uint8_t pmkid[16],
                          const uint8_t *pmk, size_t pmk_len,
                          const uint8_t *rsn_ie, size_t rsn_ie_len);

/* Trigger a scan and wait up to timeout_ms for results so cfg80211 has a
 * BSS entry for the AUTHENTICATE / CONNECT target. Returns 0 on success
 * (results received) or negative on error / timeout. */
int nl80211_sta_scan(struct nl80211_sta *st, int timeout_ms);

/* Begin the join. PSK / 802.1X issue NL80211_CMD_CONNECT. SAE kicks the
 * attached supplicant, which emits the SAE Commit via send_auth_frame;
 * ASSOCIATE is issued automatically once SAE completes. now_ms is the
 * current monotonic timestamp. Returns 0 on success. */
int nl80211_sta_start(struct nl80211_sta *st, uint64_t now_ms);

/* Pump nl80211 + AF_PACKET events for up to timeout_ms, feed the attached
 * supplicant, advance the SAE -> ASSOCIATE transition, and service the
 * supplicant retransmit tick. Returns the current supplicant state
 * (wolfip_supplicant_state_t) or negative on a hard radio error. */
int nl80211_sta_poll(struct nl80211_sta *st, int timeout_ms, uint64_t now_ms);

/* Raw fd accessors for callers running their own select() loop (e.g. the
 * wolfIP poll loop in wolfsta). */
int nl80211_sta_event_fd(const struct nl80211_sta *st);
int nl80211_sta_packet_fd(const struct nl80211_sta *st);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_NL80211_STA_H */
