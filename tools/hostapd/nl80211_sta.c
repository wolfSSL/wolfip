/* nl80211_sta.c
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

#include "nl80211_sta.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "rsn_ie.h"

#define EAPOL_ETH_TYPE      0x888EU
#define IEEE80211_HDR_LEN   24       /* mgmt frame: no QoS, no addr4       */

/* Standard cipher / AKM suite selectors (OUI 00:0F:AC). */
#define WPA_CIPHER_CCMP     0x000FAC04U
#define WPA_AKM_PSK         0x000FAC02U
#define WPA_AKM_SAE         0x000FAC08U
#define WPA_AKM_8021X       0x000FAC01U

/* NL80211_ATTR_SAE_DATA is the attribute mac80211/hwsim use to carry the
 * SAE authentication payload. It is present in modern headers; guard for
 * older toolchains. The payload starts with the Authentication
 * transaction sequence number field (NOT the algorithm number, which the
 * kernel derives from NL80211_ATTR_AUTH_TYPE = SAE). */
#ifndef NL80211_ATTR_SAE_DATA
#define NL80211_ATTR_SAE_DATA 0x9c
#endif

/* ----------------------------------------------------------------------
 * libnl request/ack plumbing
 * -------------------------------------------------------------------- */

static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                       void *arg)
{
    int *ret = (int *)arg;
    (void)nla;
    *ret = err->error;
    return NL_STOP;
}
static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *ret = (int *)arg;
    (void)msg;
    *ret = 0;
    return NL_SKIP;
}
static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *ret = (int *)arg;
    (void)msg;
    *ret = 0;
    return NL_STOP;
}

/* Multicast events carry sequence numbers that do not match any request,
 * so libnl's default NL_CB_SEQ_CHECK rejects them with -NLE_SEQ_MISMATCH.
 * Every cb used to receive multicast must install this no-op to accept
 * them (the same idiom wpa_supplicant uses). */
static int no_seq_check(struct nl_msg *msg, void *arg)
{
    (void)msg; (void)arg;
    return NL_OK;
}

/* Send msg on sk and block until ACK / ERR / FINISH. Frees msg. */
static int nl_send_msg(struct nl_sock *sk, struct nl_msg *msg)
{
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    int err = 1;

    if (cb == NULL) { nlmsg_free(msg); return -ENOMEM; }
    if (nl_send_auto(sk, msg) < 0) {
        nlmsg_free(msg);
        nl_cb_put(cb);
        return -1;
    }
    nl_cb_err(cb, NL_CB_CUSTOM, err_handler,    &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK,    NL_CB_CUSTOM, ack_handler,    &err);
    while (err > 0) {
        /* Break on a socket-level error so a transient/malformed reply that
         * never delivers ACK/ERR/FINISH cannot spin this loop forever. */
        int rc = nl_recvmsgs(sk, cb);
        if (rc < 0) { err = rc; break; }
    }
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}

/* ----------------------------------------------------------------------
 * AF_PACKET (EAPOL transport for the 4-way handshake)
 * -------------------------------------------------------------------- */

static int packet_open(struct nl80211_sta *st)
{
    struct ifreq        ifr;
    struct sockaddr_ll  sll;
    int s;

    s = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_ETH_TYPE));
    if (s < 0) { perror("socket(AF_PACKET)"); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, st->ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX"); close(s); return -1;
    }
    st->ifindex = ifr.ifr_ifindex;
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR"); close(s); return -1;
    }
    memcpy(st->sta_mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(EAPOL_ETH_TYPE);
    sll.sll_ifindex  = st->ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)"); close(s); return -1;
    }
    st->packet_sock = s;
    return 0;
}

/* Transmit an EAPOL frame over the nl80211 control port
 * (NL80211_CMD_CONTROL_PORT_FRAME). ATTR_FRAME is the bare EAPOL payload;
 * the kernel builds the 802.11 frame from ATTR_MAC (dest = AP) + the
 * control-port ethertype. This is mandatory on real SoftMAC drivers, which
 * drop EAPOL injected on the netdev data path while the controlled port is
 * unauthorized. Sent without blocking for the command ack so an inbound
 * control-port frame queued on the same socket cannot be starved; the
 * supplicant retransmits handshake frames on loss. */
static int eapol_tx(struct nl80211_sta *st, const uint8_t *frame, size_t len)
{
    struct nl_msg *msg = nlmsg_alloc();
    int rc;

    if (msg == NULL) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_CONTROL_PORT_FRAME, 0);
    NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT     (msg, NL80211_ATTR_FRAME, (int)len, frame);
    NLA_PUT     (msg, NL80211_ATTR_MAC, 6, st->bssid);
    NLA_PUT_U16 (msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, EAPOL_ETH_TYPE);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    rc = nl_send_auto(st->nl_cport, msg);
    nlmsg_free(msg);
    if (rc < 0) {
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] control-port EAPOL TX rc=%d\n", rc);
        }
        return -1;
    }
    return 0;

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* ----------------------------------------------------------------------
 * RSN IE assembly (matches akm + mfp)
 * -------------------------------------------------------------------- */

static int build_rsn_ie(struct nl80211_sta *st)
{
    uint8_t  *p   = st->rsn_ie;
    uint32_t  akm = WPA_AKM_PSK;
    uint16_t  caps = 0;

    switch (st->akm) {
        case NL80211_STA_AKM_SAE:   akm = WPA_AKM_SAE;   break;
        case NL80211_STA_AKM_8021X: akm = WPA_AKM_8021X; break;
        case NL80211_STA_AKM_PSK:
        default:                    akm = WPA_AKM_PSK;   break;
    }
    if (st->mfp == NL80211_STA_MFP_REQUIRED) {
        caps = (uint16_t)(RSN_CAP_MFPR | RSN_CAP_MFPC);
    }
    else if (st->mfp == NL80211_STA_MFP_CAPABLE) {
        caps = RSN_CAP_MFPC;
    }

    /* Element header. Body is fixed at 20 bytes (version + group cipher +
     * one pairwise + one AKM + caps). */
    *p++ = RSN_IE_ELEMENT_ID;
    *p++ = 0x14;                          /* length = 20 body bytes        */
    *p++ = 0x01; *p++ = 0x00;             /* version 1 (LE)                */
    *p++ = RSN_SUITE_OUI_0; *p++ = RSN_SUITE_OUI_1; *p++ = RSN_SUITE_OUI_2;
    *p++ = RSN_CIPHER_CCMP_128;           /* group cipher CCMP-128         */
    *p++ = 0x01; *p++ = 0x00;             /* pairwise count = 1            */
    *p++ = RSN_SUITE_OUI_0; *p++ = RSN_SUITE_OUI_1; *p++ = RSN_SUITE_OUI_2;
    *p++ = RSN_CIPHER_CCMP_128;           /* pairwise CCMP-128             */
    *p++ = 0x01; *p++ = 0x00;             /* AKM count = 1                 */
    *p++ = (uint8_t)((akm >> 24) & 0xFFU);
    *p++ = (uint8_t)((akm >> 16) & 0xFFU);
    *p++ = (uint8_t)((akm >>  8) & 0xFFU);
    *p++ = (uint8_t)( akm        & 0xFFU);
    *p++ = (uint8_t)( caps       & 0xFFU);  /* RSN caps (LE)               */
    *p++ = (uint8_t)((caps >> 8) & 0xFFU);
    st->rsn_ie_len = (size_t)(p - st->rsn_ie);
    return 0;
}

/* ----------------------------------------------------------------------
 * nl80211 commands
 * -------------------------------------------------------------------- */

/* WPA2-PSK / WPA2-Enterprise open-auth + association. Also used for a
 * WPA3-SAE PMKSA fast reconnect: AKM=SAE with the PMKID supplied (and a
 * prior NL80211_CMD_SET_PMKSA), so the kernel does open auth using the
 * cached PMKSA instead of a fresh SAE exchange. */
static int do_connect(struct nl80211_sta *st)
{
    struct nl_msg *msg = nlmsg_alloc();
    uint32_t pair[1] = { WPA_CIPHER_CCMP };
    uint32_t akm[1];

    if (msg == NULL) return -ENOMEM;
    akm[0] = (st->akm == NL80211_STA_AKM_8021X) ? WPA_AKM_8021X : WPA_AKM_PSK;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_CONNECT, 0);
    NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT     (msg, NL80211_ATTR_SSID, (int)st->ssid_len, st->ssid);
    NLA_PUT_U32 (msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    NLA_PUT_FLAG(msg, NL80211_ATTR_PRIVACY);
    NLA_PUT_U32 (msg, NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2);
    NLA_PUT     (msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                 (int)sizeof(pair), pair);
    NLA_PUT_U32 (msg, NL80211_ATTR_CIPHER_SUITE_GROUP, WPA_CIPHER_CCMP);
    NLA_PUT     (msg, NL80211_ATTR_AKM_SUITES, (int)sizeof(akm), akm);
    if (st->mfp == NL80211_STA_MFP_REQUIRED) {
        NLA_PUT_U32(msg, NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED);
    }
    else if (st->mfp == NL80211_STA_MFP_CAPABLE) {
        NLA_PUT_U32(msg, NL80211_ATTR_USE_MFP, NL80211_MFP_OPTIONAL);
    }
    /* CONTROL_PORT + CONTROL_PORT_OVER_NL80211: the supplicant owns the
     * 4-way and EAPOL flows over nl80211 (NL80211_CMD_CONTROL_PORT_FRAME),
     * not the netdev data path - real SoftMAC drivers drop EAPOL injected
     * on the data path while the controlled port is unauthorized. Frames
     * are delivered to this command socket (SOCKET_OWNER). */
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT);
    NLA_PUT_U16 (msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, EAPOL_ETH_TYPE);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_OVER_NL80211);
    NLA_PUT_FLAG(msg, NL80211_ATTR_SOCKET_OWNER);
    NLA_PUT_U32 (msg, NL80211_ATTR_WIPHY_FREQ, st->freq_mhz);
    NLA_PUT     (msg, NL80211_ATTR_IE, (int)st->rsn_ie_len, st->rsn_ie);
    NLA_PUT     (msg, NL80211_ATTR_MAC, 6, st->bssid);
    /* nl_cport = SOCKET_OWNER, so control-port EAPOL is delivered there. */
    return nl_send_msg(st->nl_cport, msg);

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* WPA3-SAE: send an Authentication frame carrying the SAE payload. body
 * is the supplicant's auth-frame body: alg(2) || seq(2) || status(2) ||
 * content. NL80211_ATTR_SAE_DATA must start at the transaction-seq field,
 * so we skip the leading 2-byte algorithm number. The kernel adds the
 * 802.11 header and sets the algorithm number from AUTH_TYPE = SAE.
 *
 * mac80211 accepts a second AUTHENTICATE for the same BSS as the SAE
 * Confirm continuation, so both Commit and Confirm take this path. */
static int do_authenticate_sae(struct nl80211_sta *st,
                               const uint8_t *body, size_t body_len)
{
    struct nl_msg *msg;
    int rc;

    if (body_len < 6) return -1;       /* need at least alg+seq+status     */
    msg = nlmsg_alloc();
    if (msg == NULL) return -ENOMEM;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_AUTHENTICATE, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT_U32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_SAE);
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, st->freq_mhz);
    NLA_PUT    (msg, NL80211_ATTR_SSID, (int)st->ssid_len, st->ssid);
    NLA_PUT    (msg, NL80211_ATTR_MAC, 6, st->bssid);
    /* Skip alg(2); SAE_DATA = seq(2) || status(2) || content. */
    NLA_PUT    (msg, NL80211_ATTR_SAE_DATA,
                (int)(body_len - 2), body + 2);
    rc = nl_send_msg(st->nl_cmd, msg);
    if (st->verbose) {
        fprintf(stderr, "[nl80211_sta] AUTHENTICATE rc=%d (%s) seq=%u\n",
                rc, rc ? strerror(rc < 0 ? -rc : rc) : "ok",
                (unsigned)(body[2] | (body[3] << 8)));
    }
    return rc;

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* Open-system AUTHENTICATE (no SAE), used for a PMKSA fast reconnect: the
 * dragonfly is skipped and the cached PMKSA is offered via the PMKID in the
 * subsequent ASSOCIATE RSN IE. */
static int do_authenticate_open(struct nl80211_sta *st)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_AUTHENTICATE, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT_U32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, st->freq_mhz);
    NLA_PUT    (msg, NL80211_ATTR_SSID, (int)st->ssid_len, st->ssid);
    NLA_PUT    (msg, NL80211_ATTR_MAC, 6, st->bssid);
    return nl_send_msg(st->nl_cmd, msg);
nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* AUTHENTICATE can fail with -ENOENT when cfg80211 has no cached BSS yet
 * (the scan that completed predated hostapd beaconing). Retry after a
 * fresh scan a few times. Used only for the SAE Commit (seq 1); the
 * Confirm runs against an already-known BSS. */
static int authenticate_sae_retry(struct nl80211_sta *st,
                                  const uint8_t *body, size_t body_len)
{
    int rc, attempt;
    for (attempt = 0; attempt < 4; attempt++) {
        rc = do_authenticate_sae(st, body, body_len);
        if (rc == 0 || rc == -ENOENT) {
            if (rc == 0) return 0;
            if (st->verbose) {
                fprintf(stderr, "[nl80211_sta] no cached BSS; rescanning "
                                "(attempt %d)\n", attempt + 1);
            }
            nl80211_sta_scan(st, 4000);
            continue;
        }
        return rc;   /* other errors: do not spin */
    }
    return rc;
}

/* WPA3-SAE: associate after SAE authentication completes. */
static int do_associate_sae(struct nl80211_sta *st)
{
    struct nl_msg *msg = nlmsg_alloc();
    uint32_t pair[1] = { WPA_CIPHER_CCMP };
    uint32_t akm[1]  = { WPA_AKM_SAE };

    if (msg == NULL) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_ASSOCIATE, 0);
    NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT     (msg, NL80211_ATTR_MAC, 6, st->bssid);
    NLA_PUT_U32 (msg, NL80211_ATTR_WIPHY_FREQ, st->freq_mhz);
    NLA_PUT     (msg, NL80211_ATTR_SSID, (int)st->ssid_len, st->ssid);
    NLA_PUT     (msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                 (int)sizeof(pair), pair);
    NLA_PUT_U32 (msg, NL80211_ATTR_CIPHER_SUITE_GROUP, WPA_CIPHER_CCMP);
    NLA_PUT     (msg, NL80211_ATTR_AKM_SUITES, (int)sizeof(akm), akm);
    NLA_PUT_U32 (msg, NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT);
    NLA_PUT_U16 (msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, EAPOL_ETH_TYPE);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_OVER_NL80211);
    NLA_PUT_FLAG(msg, NL80211_ATTR_SOCKET_OWNER);
    NLA_PUT     (msg, NL80211_ATTR_IE, (int)st->rsn_ie_len, st->rsn_ie);
    /* Sent on nl_cport so it becomes the SOCKET_OWNER and the kernel
     * delivers the control-port EAPOL frames there (read in the poll loop). */
    return nl_send_msg(st->nl_cport, msg);

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* Open the controlled port after the 4-way: mark the AP station
 * AUTHORIZED so mac80211 stops dropping non-EAPOL data frames. Without
 * this the PTK/GTK are installed but DHCP / IP traffic is silently
 * discarded by the still-blocked controlled port. */
static int do_set_authorized(struct nl80211_sta *st)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct nl80211_sta_flag_update flags;
    if (msg == NULL) return -ENOMEM;
    memset(&flags, 0, sizeof(flags));   /* serialized whole; no uninit padding */
    flags.mask = (1U << NL80211_STA_FLAG_AUTHORIZED);
    flags.set  = (1U << NL80211_STA_FLAG_AUTHORIZED);
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_SET_STATION, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT    (msg, NL80211_ATTR_MAC, 6, st->bssid);
    NLA_PUT    (msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);
    return nl_send_msg(st->nl_cmd, msg);
nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

static int do_disconnect(struct nl80211_sta *st)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_DISCONNECT, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, st->ifindex);
    /* The association is SOCKET_OWNER-bound to nl_cport (do_associate_sae /
     * do_connect), so the teardown must come from that socket or the kernel
     * leaves the interface associated and the next scan/auth fails. */
    return nl_send_msg(st->nl_cport, msg);
nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* Install PTK (pairwise) or GTK (group) into the kernel so encrypted data
 * can flow after the 4-way handshake. Uses flat NL80211_ATTR_KEY_* attrs
 * (as wpa_supplicant does). key_len 16 => CCMP-128. */
static int do_install_key(struct nl80211_sta *st, int pairwise,
                          uint8_t idx, const uint8_t *key, size_t key_len)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_NEW_KEY, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, st->ifindex);
    NLA_PUT    (msg, NL80211_ATTR_KEY_DATA, (int)key_len, key);
    NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER, WPA_CIPHER_CCMP);
    NLA_PUT_U8 (msg, NL80211_ATTR_KEY_IDX, idx);
    if (pairwise) {
        NLA_PUT    (msg, NL80211_ATTR_MAC, 6, st->bssid);
        NLA_PUT_U32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_PAIRWISE);
    }
    else {
        NLA_PUT_U32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
    }
    if (nl_send_msg(st->nl_cmd, msg) != 0) return -1;

    /* For the group key, also mark it the default RX key. */
    if (!pairwise) {
        msg = nlmsg_alloc();
        if (msg == NULL) return -ENOMEM;
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                    NL80211_CMD_SET_KEY, 0);
        NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, st->ifindex);
        NLA_PUT_U8  (msg, NL80211_ATTR_KEY_IDX, idx);
        NLA_PUT_FLAG(msg, NL80211_ATTR_KEY_DEFAULT);
        if (nl_send_msg(st->nl_cmd, msg) != 0) return -1;
    }
    return 0;

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* ----------------------------------------------------------------------
 * supplicant ops (wired to this radio)
 * -------------------------------------------------------------------- */

static int ops_send_eapol(void *ctx, const uint8_t *frame, size_t len)
{
    struct nl80211_sta *st = (struct nl80211_sta *)ctx;
    return eapol_tx(st, frame, len);
}

static int ops_install_key(void *ctx, wolfip_supplicant_keytype_t kt,
                           uint8_t idx, const uint8_t *key, size_t len)
{
    struct nl80211_sta *st = (struct nl80211_sta *)ctx;
    int pairwise = (kt == SUPP_KEY_PAIRWISE) ? 1 : 0;
    if (st->verbose) {
        fprintf(stderr, "[nl80211_sta] install %s key idx=%u len=%zu\n",
                pairwise ? "pairwise" : "group", idx, len);
    }
    return do_install_key(st, pairwise, idx, key, len);
}

static int ops_send_auth_frame(void *ctx, const uint8_t *frame, size_t len)
{
    struct nl80211_sta *st = (struct nl80211_sta *)ctx;
    if (st->verbose) {
        fprintf(stderr, "[nl80211_sta] SAE auth tx body=%zuB\n", len);
    }
    return authenticate_sae_retry(st, frame, len);
}

/* ----------------------------------------------------------------------
 * event pump
 * -------------------------------------------------------------------- */

static uint64_t g_event_now_ms;   /* set per poll() round for the cb       */

static int event_cb(struct nl_msg *msg, void *arg)
{
    struct nl80211_sta *st   = (struct nl80211_sta *)arg;
    struct nlmsghdr    *nlh  = nlmsg_hdr(msg);
    struct genlmsghdr  *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
    struct nlattr      *attrs[NL80211_ATTR_MAX + 1];

    nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    switch (gnlh->cmd) {
    case NL80211_CMD_CONTROL_PORT_FRAME: {
        /* Inbound EAPOL over the nl80211 control port (4-way M1/M3, group
         * key M1). ATTR_FRAME is the bare EAPOL payload - hand it straight
         * to the supplicant, same as the old AF_PACKET data-path RX did. */
        const uint8_t *fr;
        int            fr_len;
        if (attrs[NL80211_ATTR_FRAME] == NULL || st->supp == NULL) {
            return NL_SKIP;
        }
        fr     = (const uint8_t *)nla_data(attrs[NL80211_ATTR_FRAME]);
        fr_len = nla_len(attrs[NL80211_ATTR_FRAME]);
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] EAPOL RX (control port) len=%d\n",
                    fr_len);
        }
        wolfip_supplicant_rx(st->supp, fr, (size_t)fr_len, g_event_now_ms);
        return NL_SKIP;
    }
    case NL80211_CMD_AUTHENTICATE: {
        /* PMKSA fast reconnect: this is the Open-auth success (no SAE).
         * Proceed straight to ASSOCIATE with the PMKID-bearing RSN IE. */
        const uint8_t *fr;
        int            fr_len;
        if (st->pmksa_reconnect && !st->assoc_sent) {
            if (st->verbose) {
                fprintf(stderr, "[nl80211_sta] open auth done; associating "
                                "(PMKSA)\n");
            }
            if (do_associate_sae(st) != 0) st->failed = 1;
            else st->assoc_sent = 1;
            return NL_SKIP;
        }
        /* Otherwise: a received SAE Auth frame (Commit / Confirm).
         * ATTR_FRAME is the full 802.11 mgmt frame; strip the 24-byte header
         * so what is left is alg(2) || seq(2) || status(2) || content -
         * exactly the body wolfip_supplicant_rx_auth_frame() expects. */
        if (attrs[NL80211_ATTR_FRAME] == NULL) return NL_SKIP;
        fr     = (const uint8_t *)nla_data(attrs[NL80211_ATTR_FRAME]);
        fr_len = nla_len(attrs[NL80211_ATTR_FRAME]);
        if (fr_len <= IEEE80211_HDR_LEN) return NL_SKIP;
        if (fr[0] != 0xB0) return NL_SKIP;            /* not an Auth frame */
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] RX auth via CMD_AUTHENTICATE "
                            "len=%d\n", fr_len);
        }
        if (st->supp != NULL) {
            wolfip_supplicant_rx_auth_frame(st->supp,
                fr + IEEE80211_HDR_LEN,
                (size_t)(fr_len - IEEE80211_HDR_LEN), g_event_now_ms);
            if (!st->sae_authenticated
                && wolfip_supplicant_state(st->supp)
                       == SUPP_STATE_4WAY_M1_WAIT) {
                st->sae_authenticated = 1;
                if (st->verbose) {
                    fprintf(stderr,
                        "[nl80211_sta] SAE complete; associating\n");
                }
                if (do_associate_sae(st) != 0) {
                    fprintf(stderr, "[nl80211_sta] ASSOCIATE failed\n");
                    st->failed = 1;
                }
                else {
                    st->assoc_sent = 1;
                }
            }
        }
        return NL_SKIP;
    }
    case NL80211_CMD_ASSOCIATE: {
        /* The CMD_ASSOCIATE event carries the received (Re)Assoc Response
         * as NL80211_ATTR_FRAME; the status code is inside that frame
         * (mgmt hdr[24] + capability[2] -> status at offset 26), NOT in
         * NL80211_ATTR_STATUS_CODE. */
        uint16_t status = 0xFFFF;
        if (attrs[NL80211_ATTR_FRAME] != NULL) {
            const uint8_t *fr = (const uint8_t *)
                                nla_data(attrs[NL80211_ATTR_FRAME]);
            int fr_len = nla_len(attrs[NL80211_ATTR_FRAME]);
            if (fr_len >= 28) {
                status = (uint16_t)(fr[26] | (fr[27] << 8));
            }
        }
        else if (attrs[NL80211_ATTR_STATUS_CODE] != NULL) {
            status = nla_get_u16(attrs[NL80211_ATTR_STATUS_CODE]);
        }
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] ASSOCIATE status=%u\n", status);
        }
        if (status == 0) {
            st->associated = 1;
            /* PMKSA reconnect: no SAE ran, so the supplicant is still IDLE
             * (armed via pmksa_reconnect). Kick it into the 4-way now. */
            if (st->pmksa_reconnect && st->supp != NULL
                && wolfip_supplicant_state(st->supp) == SUPP_STATE_IDLE) {
                wolfip_supplicant_kick(st->supp, g_event_now_ms);
            }
        }
        else {
            st->failed = 1;
        }
        return NL_SKIP;
    }
    case NL80211_CMD_CONNECT: {
        uint16_t status = 0xFFFF;
        if (attrs[NL80211_ATTR_STATUS_CODE] != NULL) {
            status = nla_get_u16(attrs[NL80211_ATTR_STATUS_CODE]);
        }
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] CONNECT status=%u\n", status);
        }
        if (status == 0) {
            st->associated = 1;
            /* CONNECT-path AKMs (PSK + 802.1X/EAP) need a kick out of IDLE
             * once associated. kick() does the mode-appropriate transition:
             * PSK -> 4WAY_M1_WAIT (accept M1), EAP -> EAP_IDENTITY_WAIT
             * (accept the AP's EAP-Request/Identity). SAE is not here - it
             * starts via the AUTHENTICATE path, not CONNECT. */
            if (st->supp != NULL
                && (st->akm == NL80211_STA_AKM_PSK
                    || st->akm == NL80211_STA_AKM_8021X)
                && wolfip_supplicant_state(st->supp) == SUPP_STATE_IDLE) {
                wolfip_supplicant_kick(st->supp, g_event_now_ms);
            }
        }
        else {
            st->failed = 1;
        }
        return NL_SKIP;
    }
    case NL80211_CMD_DISCONNECT:
        if (st->expect_disconnect) {
            st->expect_disconnect = 0;
            if (st->verbose) {
                fprintf(stderr, "[nl80211_sta] DISCONNECT (self, ignored)\n");
            }
            return NL_SKIP;
        }
        if (st->verbose) fprintf(stderr, "[nl80211_sta] DISCONNECT\n");
        st->failed = 1;
        return NL_SKIP;
    case NL80211_CMD_FRAME: {
        /* Some mac80211 paths surface the peer SAE Auth as CMD_FRAME
         * rather than CMD_AUTHENTICATE. Handle both identically. */
        const uint8_t *fr;
        int            fr_len;
        if (attrs[NL80211_ATTR_FRAME] == NULL) return NL_SKIP;
        fr     = (const uint8_t *)nla_data(attrs[NL80211_ATTR_FRAME]);
        fr_len = nla_len(attrs[NL80211_ATTR_FRAME]);
        if (fr_len <= IEEE80211_HDR_LEN || fr[0] != 0xB0) return NL_SKIP;
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] RX auth via CMD_FRAME len=%d\n",
                    fr_len);
        }
        if (st->supp != NULL) {
            wolfip_supplicant_rx_auth_frame(st->supp,
                fr + IEEE80211_HDR_LEN,
                (size_t)(fr_len - IEEE80211_HDR_LEN), g_event_now_ms);
            if (!st->sae_authenticated
                && wolfip_supplicant_state(st->supp)
                       == SUPP_STATE_4WAY_M1_WAIT) {
                st->sae_authenticated = 1;
                if (do_associate_sae(st) != 0) st->failed = 1;
                else st->assoc_sent = 1;
            }
        }
        return NL_SKIP;
    }
    default:
        return NL_SKIP;
    }
}

/* ----------------------------------------------------------------------
 * scan (so cfg80211 has a BSS entry for AUTHENTICATE / CONNECT)
 * -------------------------------------------------------------------- */

static int trigger_scan(struct nl80211_sta *st)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct nl_msg *ssids;
    int rc;
    if (msg == NULL) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, st->nl_family, 0, 0,
                NL80211_CMD_TRIGGER_SCAN, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, st->ifindex);
    /* Active scan for our SSID (and wildcard) speeds up hidden / quiet
     * APs. A nested SSIDs attribute with one zero-length entry requests a
     * wildcard probe. */
    ssids = nlmsg_alloc();
    if (ssids == NULL) { nlmsg_free(msg); return -ENOMEM; }
    nla_put(ssids, 1, (int)st->ssid_len, st->ssid);
    nla_put(ssids, 2, 0, "");
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
    nlmsg_free(ssids);
    rc = nl_send_msg(st->nl_cmd, msg);
    return rc;

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

/* Minimal scan-result waiter: watch the mlme/scan multicast for
 * NEW_SCAN_RESULTS. We subscribe to the "scan" group only for the
 * duration of the wait. */
static int scan_done_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr   *nlh  = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
    int *done = (int *)arg;
    if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS
        || gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
        *done = 1;
        return NL_STOP;
    }
    return NL_SKIP;
}

/* Block (via select) until scan_done_cb sets *done or the timeout. */
static void wait_scan_event(struct nl_sock *ssk, struct nl_cb *cb,
                            int *done, int timeout_ms)
{
    int fd = nl_socket_get_fd(ssk);
    int waited = 0;
    while (!*done && waited < timeout_ms) {
        struct timeval tv = {0, 200000};
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0
            && FD_ISSET(fd, &rfds)) {
            nl_recvmsgs(ssk, cb);
        }
        waited += 200;
    }
}

int nl80211_sta_scan(struct nl80211_sta *st, int timeout_ms)
{
    struct nl_sock *ssk;
    struct nl_cb   *cb;
    int   grp;
    int   done = 0;
    int   rc;

    ssk = nl_socket_alloc();
    if (ssk == NULL) return -ENOMEM;
    if (genl_connect(ssk) < 0) { nl_socket_free(ssk); return -1; }
    grp = genl_ctrl_resolve_grp(ssk, "nl80211", "scan");
    if (grp < 0) { nl_socket_free(ssk); return -1; }
    nl_socket_add_membership(ssk, grp);
    nl_socket_disable_seq_check(ssk);

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (cb == NULL) { nl_socket_free(ssk); return -ENOMEM; }
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, scan_done_cb, &done);

    /* If a scan is already in flight (TRIGGER_SCAN returns -EBUSY), its
     * results may predate the AP coming up. Drain it, then trigger our
     * own fresh scan so the BSS cache reflects the current AP. */
    rc = trigger_scan(st);
    if (rc != 0) {
        if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] scan busy (rc=%d); draining "
                            "then re-triggering\n", rc);
        }
        wait_scan_event(ssk, cb, &done, timeout_ms);
        done = 0;
        trigger_scan(st);
    }
    wait_scan_event(ssk, cb, &done, timeout_ms);

    nl_cb_put(cb);
    nl_socket_free(ssk);
    if (st->verbose) {
        fprintf(stderr, "[nl80211_sta] scan %s\n",
                done ? "results ready" : "timed out");
    }
    return done ? 0 : -1;
}

/* ----------------------------------------------------------------------
 * public API
 * -------------------------------------------------------------------- */

int nl80211_sta_init(struct nl80211_sta *st, const char *ifname)
{
    int grp;

    if (st == NULL || ifname == NULL) return -1;
    memset(st, 0, sizeof(*st));
    st->packet_sock = -1;
    strncpy(st->ifname, ifname, sizeof(st->ifname) - 1);

    if (packet_open(st) != 0) return -1;

    st->nl_cmd   = nl_socket_alloc();
    st->nl_event = nl_socket_alloc();
    st->nl_cport = nl_socket_alloc();
    if (st->nl_cmd == NULL || st->nl_event == NULL || st->nl_cport == NULL) {
        nl80211_sta_cleanup(st);
        return -1;
    }
    if (genl_connect(st->nl_cmd) < 0 || genl_connect(st->nl_event) < 0
        || genl_connect(st->nl_cport) < 0) {
        nl80211_sta_cleanup(st);
        return -1;
    }
    /* Control-port frames are unsolicited (kernel-generated seq), so the
     * owner socket must skip libnl's sequence-number check like nl_event. */
    nl_socket_disable_seq_check(st->nl_cport);
    st->nl_family = genl_ctrl_resolve(st->nl_cmd, "nl80211");
    if (st->nl_family < 0) {
        fprintf(stderr, "[nl80211_sta] nl80211 family not available\n");
        nl80211_sta_cleanup(st);
        return -1;
    }
    grp = genl_ctrl_resolve_grp(st->nl_event, "nl80211", "mlme");
    if (grp < 0) {
        fprintf(stderr, "[nl80211_sta] resolve mlme group failed: %d\n", grp);
        nl80211_sta_cleanup(st);
        return -1;
    }
    {
        int mrc = nl_socket_add_membership(st->nl_event, grp);
        if (mrc < 0) {
            fprintf(stderr, "[nl80211_sta] add mlme membership failed: %d "
                            "(%s)\n", mrc, nl_geterror(mrc));
            nl80211_sta_cleanup(st);
            return -1;
        }
    }
    nl_socket_disable_seq_check(st->nl_event);
    return 0;
}

void nl80211_sta_cleanup(struct nl80211_sta *st)
{
    if (st == NULL) return;
    if (st->nl_cmd != NULL && st->associated) {
        do_disconnect(st);
    }
    if (st->packet_sock >= 0) { close(st->packet_sock); st->packet_sock = -1; }
    if (st->nl_event != NULL) { nl_socket_free(st->nl_event); st->nl_event = NULL; }
    if (st->nl_cport != NULL) { nl_socket_free(st->nl_cport); st->nl_cport = NULL; }
    if (st->nl_cmd   != NULL) { nl_socket_free(st->nl_cmd);   st->nl_cmd   = NULL; }
}

void nl80211_sta_reset(struct nl80211_sta *st)
{
    if (st == NULL) return;
    if (st->nl_cmd != NULL && st->associated) {
        do_disconnect(st);
        /* The kernel echoes our DISCONNECT back as a CMD_DISCONNECT event
         * that can land in the next pass's poll loop; swallow that one so
         * it is not mistaken for a reconnect failure. */
        st->expect_disconnect = 1;
    }
    st->started          = 0;
    st->associated       = 0;
    st->sae_authenticated = 0;
    st->assoc_sent       = 0;
    st->port_authorized  = 0;
    st->failed           = 0;
    /* Return to a pristine, non-PMKSA state so a reset followed by a plain
     * SAE start does not accidentally take the open-auth PMKSA branch. A
     * PMKSA fast reconnect re-arms this via nl80211_sta_set_pmksa() after
     * the reset. */
    st->pmksa_reconnect  = 0;
    st->pmk_len          = 0;
}

int nl80211_sta_set_target(struct nl80211_sta *st, const char *ssid,
                           const uint8_t bssid[6], uint32_t freq_mhz,
                           enum nl80211_sta_akm akm, enum nl80211_sta_mfp mfp)
{
    size_t slen;
    if (st == NULL || ssid == NULL || bssid == NULL) return -1;
    slen = strlen(ssid);
    if (slen > WOLFIP_SUPPLICANT_MAX_SSID) return -1;
    memcpy(st->ssid, ssid, slen);
    st->ssid[slen] = '\0';
    st->ssid_len   = slen;
    memcpy(st->bssid, bssid, 6);
    st->freq_mhz = freq_mhz;
    st->akm      = akm;
    st->mfp      = mfp;
    return build_rsn_ie(st);
}

void nl80211_sta_supplicant_ops(struct nl80211_sta *st,
                                struct wolfip_supplicant_ops *ops)
{
    if (ops == NULL) return;
    ops->send_eapol      = ops_send_eapol;
    ops->install_key     = ops_install_key;
    ops->send_auth_frame = ops_send_auth_frame;
    ops->ctx             = st;
}

void nl80211_sta_attach(struct nl80211_sta *st,
                        struct wolfip_supplicant *supp)
{
    if (st != NULL) st->supp = supp;
}

int nl80211_sta_set_pmksa(struct nl80211_sta *st,
                          const uint8_t pmkid[16],
                          const uint8_t *pmk, size_t pmk_len,
                          const uint8_t *rsn_ie, size_t rsn_ie_len)
{
    if (st == NULL || pmkid == NULL || pmk == NULL || rsn_ie == NULL) {
        return -1;
    }
    if (pmk_len > sizeof(st->pmk) || rsn_ie_len > sizeof(st->rsn_ie)) {
        return -1;
    }
    memcpy(st->pmkid, pmkid, 16);
    memcpy(st->pmk, pmk, pmk_len);
    st->pmk_len = pmk_len;
    /* Use the PMKID-bearing RSN IE for the assoc so it matches the M2 IE
     * (and offers the PMKID that lets hostapd skip SAE). */
    memcpy(st->rsn_ie, rsn_ie, rsn_ie_len);
    st->rsn_ie_len = rsn_ie_len;
    st->pmksa_reconnect = 1;
    return 0;
}

int nl80211_sta_start(struct nl80211_sta *st, uint64_t now_ms)
{
    if (st == NULL) return -1;
    /* PMKSA fast reconnect: open auth via the cached PMKSA, no SAE. The
     * supplicant was armed with wolfip_supplicant_pmksa_reconnect(), so its
     * kick() (driven on CONNECT success) jumps straight to the 4-way. */
    if (st->pmksa_reconnect) {
        if (nl80211_sta_scan(st, 5000) != 0 && st->verbose) {
            fprintf(stderr, "[nl80211_sta] scan returned no results; "
                            "proceeding anyway\n");
        }
        /* Open auth (no SAE); the PMKID in the ASSOCIATE RSN IE tells
         * hostapd to use the cached PMKSA and go straight to the 4-way. */
        if (do_authenticate_open(st) != 0) {
            fprintf(stderr, "[nl80211_sta] PMKSA open-auth submit failed\n");
            return -1;
        }
        st->started = 1;
        return 0;
    }
    if (st->akm == NL80211_STA_AKM_SAE) {
        /* mac80211 requires a cached BSS for AUTHENTICATE. */
        if (nl80211_sta_scan(st, 5000) != 0 && st->verbose) {
            fprintf(stderr, "[nl80211_sta] scan returned no results; "
                            "proceeding anyway\n");
        }
        if (st->supp == NULL) {
            fprintf(stderr, "[nl80211_sta] SAE requires an attached "
                            "supplicant\n");
            return -1;
        }
        /* kick() generates the SAE Commit, which flows out through
         * ops_send_auth_frame -> do_authenticate_sae. */
        if (wolfip_supplicant_kick(st->supp, now_ms) != 0) {
            fprintf(stderr, "[nl80211_sta] supplicant kick failed\n");
            return -1;
        }
        st->started = 1;
        return 0;
    }
    /* PSK / 802.1X. */
    if (do_connect(st) != 0) {
        fprintf(stderr, "[nl80211_sta] CONNECT submit failed\n");
        return -1;
    }
    st->started = 1;
    return 0;
}

int nl80211_sta_poll(struct nl80211_sta *st, int timeout_ms, uint64_t now_ms)
{
    struct nl_cb *cb;
    fd_set rfds;
    struct timeval tv;
    int nl_fd, cmd_fd, pk_fd, max_fd, sel;

    if (st == NULL || st->supp == NULL) return -1;
    g_event_now_ms = now_ms;

    nl_fd  = nl_socket_get_fd(st->nl_event);
    cmd_fd = nl_socket_get_fd(st->nl_cport); /* control-port EAPOL RX owner */
    pk_fd  = st->packet_sock;
    max_fd = nl_fd;
    if (cmd_fd > max_fd) max_fd = cmd_fd;
    if (pk_fd  > max_fd) max_fd = pk_fd;

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&rfds);
    FD_SET(nl_fd,  &rfds);
    FD_SET(cmd_fd, &rfds);
    FD_SET(pk_fd,  &rfds);

    sel = select(max_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
        if (errno == EINTR) return (int)wolfip_supplicant_state(st->supp);
        return -1;
    }
    if (sel > 0) {
        if (FD_ISSET(nl_fd, &rfds)) {
            int rc;
            cb = nl_cb_alloc(NL_CB_DEFAULT);
            if (cb != NULL) {
                nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
                          no_seq_check, NULL);
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_cb, st);
                rc = nl_recvmsgs(st->nl_event, cb);
                if (st->verbose && rc < 0) {
                    fprintf(stderr, "[nl80211_sta] nl_recvmsgs rc=%d (%s)\n",
                            rc, nl_geterror(rc));
                }
                nl_cb_put(cb);
            }
        }
        if (FD_ISSET(cmd_fd, &rfds)) {
            /* Inbound EAPOL over the control port is delivered to nl_cport
             * (the SOCKET_OWNER of the association). Dispatch via event_cb,
             * which handles NL80211_CMD_CONTROL_PORT_FRAME and ignores the
             * EAPOL-TX command acks that also land here. */
            cb = nl_cb_alloc(NL_CB_DEFAULT);
            if (cb != NULL) {
                nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
                          no_seq_check, NULL);
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_cb, st);
                nl_recvmsgs(st->nl_cport, cb);
                nl_cb_put(cb);
            }
        }
        if (FD_ISSET(pk_fd, &rfds)) {
            uint8_t buf[1600];
            ssize_t n = recv(pk_fd, buf, sizeof(buf), 0);
            /* Skip our own outbound copies (src == our MAC). */
            if (n >= 14 && memcmp(&buf[6], st->sta_mac, 6) != 0) {
                wolfip_supplicant_rx(st->supp, buf + 14,
                                     (size_t)(n - 14), now_ms);
            }
        }
    }
    wolfip_supplicant_tick(st->supp, now_ms);
    /* Once the 4-way completes, open the controlled port so data flows. */
    if (!st->port_authorized
        && wolfip_supplicant_state(st->supp) == SUPP_STATE_AUTHENTICATED) {
        st->port_authorized = 1;
        if (do_set_authorized(st) != 0 && st->verbose) {
            fprintf(stderr, "[nl80211_sta] set-authorized failed "
                            "(data may be blocked)\n");
        }
        else if (st->verbose) {
            fprintf(stderr, "[nl80211_sta] controlled port authorized\n");
        }
    }
    if (st->failed) return -1;
    return (int)wolfip_supplicant_state(st->supp);
}

int nl80211_sta_event_fd(const struct nl80211_sta *st)
{
    if (st == NULL || st->nl_event == NULL) return -1;
    return nl_socket_get_fd(st->nl_event);
}

int nl80211_sta_packet_fd(const struct nl80211_sta *st)
{
    if (st == NULL) return -1;
    return st->packet_sock;
}
