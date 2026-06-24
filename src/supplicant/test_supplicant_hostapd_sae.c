/* test_supplicant_hostapd_sae.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Real-authenticator interop test for WPA3-Personal (SAE). The wolfIP
 * supplicant runs in WOLFIP_AUTH_SAE mode; this program plumbs its
 * send_auth_frame / rx_auth_frame surface to the Linux mac80211 stack
 * via nl80211 external-auth, and its EAPOL surface to AF_PACKET on the
 * STA wlan netdev (same path the PSK test uses).
 *
 * Flow:
 *   1. NL80211_CMD_CONNECT with EXTERNAL_AUTH_SUPPORT + AKM=SAE + MFP-req
 *   2. On NL80211_CMD_EXTERNAL_AUTH event: kick supplicant -> Commit
 *   3. supp send_auth_frame -> wrap with 24B 802.11 MAC hdr -> CMD_FRAME
 *   4. NL80211_CMD_FRAME events (peer Auth) -> strip hdr -> supplicant
 *   5. Supplicant reaches 4WAY_M1_WAIT -> send EXTERNAL_AUTH success
 *   6. Kernel completes association; EAPOL flows via AF_PACKET
 *   7. Existing 4-way handshake to AUTHENTICATED
 *
 * NOTE - hwsim limitation:
 *   The CONNECT+EXTERNAL_AUTH_SUPPORT path is the cfg80211 surface used
 *   by FullMAC drivers (brcmfmac on CYW43439, our actual ship target).
 *   mac80211_hwsim is a SoftMAC driver: it advertises "SAE with
 *   AUTHENTICATE command" only, and silently ignores
 *   EXTERNAL_AUTH_SUPPORT on CONNECT, falling back to internal open
 *   auth (which hostapd then rejects). To validate this code path
 *   against hostapd you need either:
 *     (a) a FullMAC driver that honors EXTERNAL_AUTH_FOR_CONNECT, or
 *     (b) a rewrite using NL80211_CMD_AUTHENTICATE+ASSOCIATE (the
 *         SoftMAC SAE path that wpa_supplicant uses on hwsim).
 *   Real-hardware validation of this binary happens in Phase D on
 *   CYW43439 (FullMAC), not under hwsim.
 *
 * Only built when WOLFIP_ENABLE_SAE=1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE

#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "supplicant.h"
#include "rsn_ie.h"
#include "sae_crypto.h"

#define EAPOL_ETH_TYPE 0x888EU

/* WPA3-SAE RSN IE: same as WPA2-PSK but AKM=SAE (00:0F:AC:08), and
 * RSN capabilities byte 1 sets MFP Required (bit 6) + MFP Capable (bit 7). */
static const uint8_t WPA3_SAE_RSN_IE[] = {
    0x30, 0x14,                 /* element id, length                */
    0x01, 0x00,                 /* version 1                         */
    0x00, 0x0F, 0xAC, 0x04,     /* group cipher CCMP-128             */
    0x01, 0x00,                 /* pairwise count 1                  */
    0x00, 0x0F, 0xAC, 0x04,     /* pairwise CCMP-128                 */
    0x01, 0x00,                 /* AKM count 1                       */
    0x00, 0x0F, 0xAC, 0x08,     /* AKM SAE                           */
    0x00, 0xC0                  /* RSN caps: MFPR=1 + MFPC=1         */
};
#define WPA_CIPHER_CCMP 0x000FAC04U
#define WPA_AKM_SAE     0x000FAC08U

/* 802.11 Auth-frame fixed header (24 bytes, no QoS, no addr4). */
#define IEEE80211_HDR_LEN 24

struct test_ctx {
    char                       ifname[IFNAMSIZ];
    int                        ifindex;
    uint8_t                    sta_mac[6];
    uint8_t                    bssid[6];
    int                        packet_sock;
    struct nl_sock            *nl_cmd;
    struct nl_sock            *nl_event;
    int                        nl_family;
    struct wolfip_supplicant  *supp;
    int                        sae_started;
    int                        kernel_connected;
    int                        done;
    int                        failed;
};
static struct test_ctx CTX;
static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

/* ---- AF_PACKET (EAPOL transport for the post-SAE 4-way) ---- */

static int packet_open(const char *ifname, struct test_ctx *c)
{
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int s = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_ETH_TYPE));
    if (s < 0) { perror("socket(AF_PACKET)"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { close(s); return -1; }
    c->ifindex = ifr.ifr_ifindex;
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { close(s); return -1; }
    memcpy(c->sta_mac, ifr.ifr_hwaddr.sa_data, 6);
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(EAPOL_ETH_TYPE);
    sll.sll_ifindex  = c->ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(s); return -1;
    }
    c->packet_sock = s;
    return 0;
}

/* ---- nl80211 helpers ---- */

static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int *ret = arg; (void)nla;
    *ret = err->error;
    return NL_STOP;
}
static int finish_handler(struct nl_msg *msg, void *arg)
{ int *ret = arg; (void)msg; *ret = 0; return NL_SKIP; }
static int ack_handler(struct nl_msg *msg, void *arg)
{ int *ret = arg; (void)msg; *ret = 0; return NL_STOP; }

static int nl_send_msg(struct nl_sock *sk, struct nl_msg *msg)
{
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    int err = 1;
    if (!cb) { nlmsg_free(msg); return -ENOMEM; }
    if (nl_send_auto(sk, msg) < 0) {
        nlmsg_free(msg); nl_cb_put(cb); return -1;
    }
    nl_cb_err(cb, NL_CB_CUSTOM, err_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK,    NL_CB_CUSTOM, ack_handler,    &err);
    while (err > 0) nl_recvmsgs(sk, cb);
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}

/* Register interest in receiving Authentication management frames
 * (type=mgmt, subtype=11 -> frame_type 0x00B0). */
static int register_auth_frames(struct test_ctx *c)
{
    struct nl_msg *msg = nlmsg_alloc();
    uint8_t match_byte = 0;
    if (!msg) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, c->nl_family, 0, 0,
                NL80211_CMD_REGISTER_FRAME, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, c->ifindex);
    NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, 0x00B0);
    /* FRAME_MATCH must exist; use 1-byte zero payload to ensure the
     * attribute is materially emitted (libnl may elide len=0 puts on
     * some versions). The kernel matches prefix bytes; a leading
     * zero byte still matches Auth-frame bodies (alg field LSB = 3
     * for SAE, but the kernel only matches on the body portion AFTER
     * the 802.11 header, and the first byte of Auth body is alg
     * low byte = 0x03 for SAE). To match all Auth frames, use a
     * single match byte of value 0xFF which... actually just match
     * all by passing a single 0 byte; many drivers accept the
     * trailing match length as a true prefix and match it leniently.
     */
    NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, 1, &match_byte);
    /* Use the cmd socket - some kernels reject REGISTER_FRAME on
     * sockets already subscribed to mlme multicast. wpa_supplicant
     * uses a dedicated nl_mgmt socket for this; we accept the
     * simplification of receiving the registered frames on the same
     * socket we send REGISTER_FRAME on (so cmd socket here). */
    return nl_send_msg(c->nl_cmd, msg);
nla_put_failure:
    nlmsg_free(msg); return -EMSGSIZE;
}

/* Issue NL80211_CMD_CONNECT with EXTERNAL_AUTH_SUPPORT + SAE AKM. */
static int do_connect_sae(struct test_ctx *c, const char *ssid,
                          uint32_t freq_mhz)
{
    struct nl_msg *msg = nlmsg_alloc();
    uint32_t pair[1]  = { WPA_CIPHER_CCMP };
    uint32_t akm[1]   = { WPA_AKM_SAE };
    if (!msg) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, c->nl_family, 0, 0,
                NL80211_CMD_CONNECT, 0);
    NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, c->ifindex);
    NLA_PUT     (msg, NL80211_ATTR_SSID, (int)strlen(ssid), ssid);
    NLA_PUT_U32 (msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_SAE);
    NLA_PUT_FLAG(msg, NL80211_ATTR_PRIVACY);
    NLA_PUT_U32 (msg, NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2);
    NLA_PUT     (msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                 (int)sizeof(pair), pair);
    NLA_PUT_U32 (msg, NL80211_ATTR_CIPHER_SUITE_GROUP, WPA_CIPHER_CCMP);
    NLA_PUT     (msg, NL80211_ATTR_AKM_SUITES, (int)sizeof(akm), akm);
    NLA_PUT_U32 (msg, NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT);
    NLA_PUT_U16 (msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
                 EAPOL_ETH_TYPE);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    NLA_PUT_FLAG(msg, NL80211_ATTR_EXTERNAL_AUTH_SUPPORT);
    NLA_PUT_FLAG(msg, NL80211_ATTR_SOCKET_OWNER);
    NLA_PUT_U32 (msg, NL80211_ATTR_WIPHY_FREQ, freq_mhz);
    NLA_PUT     (msg, NL80211_ATTR_IE,
                 (int)sizeof(WPA3_SAE_RSN_IE), WPA3_SAE_RSN_IE);
    NLA_PUT     (msg, NL80211_ATTR_MAC, 6, c->bssid);
    return nl_send_msg(c->nl_cmd, msg);
nla_put_failure:
    nlmsg_free(msg); return -EMSGSIZE;
}

/* Acknowledge EXTERNAL_AUTH result back to kernel. */
static int do_external_auth_result(struct test_ctx *c, uint16_t status,
                                   const char *ssid)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, c->nl_family, 0, 0,
                NL80211_CMD_EXTERNAL_AUTH, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, c->ifindex);
    NLA_PUT_U16(msg, NL80211_ATTR_STATUS_CODE, status);
    NLA_PUT    (msg, NL80211_ATTR_SSID, (int)strlen(ssid), ssid);
    NLA_PUT    (msg, NL80211_ATTR_BSSID, 6, c->bssid);
    return nl_send_msg(c->nl_cmd, msg);
nla_put_failure:
    nlmsg_free(msg); return -EMSGSIZE;
}

/* Send an 802.11 Authentication frame via NL80211_CMD_FRAME. body =
 * SAE auth-frame body (alg/seq/status/content); we prepend the 24-byte
 * 802.11 MAC header. */
static int send_mgmt_auth(struct test_ctx *c,
                          const uint8_t *body, size_t body_len)
{
    struct nl_msg *msg;
    uint8_t        frame[1024];
    if (IEEE80211_HDR_LEN + body_len > sizeof(frame)) return -1;

    /* 802.11 Auth frame: subtype=11 (Auth) → frame_control = 0xB0 0x00. */
    frame[0]  = 0xB0; frame[1] = 0x00;     /* fc                  */
    frame[2]  = 0x00; frame[3] = 0x00;     /* duration            */
    memcpy(&frame[4],  c->bssid,    6);    /* addr1 (DA)          */
    memcpy(&frame[10], c->sta_mac,  6);    /* addr2 (SA)          */
    memcpy(&frame[16], c->bssid,    6);    /* addr3 (BSSID)       */
    frame[22] = 0x00; frame[23] = 0x00;    /* seq_ctrl (kernel)   */
    memcpy(&frame[24], body, body_len);

    msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, c->nl_family, 0, 0,
                NL80211_CMD_FRAME, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, c->ifindex);
    NLA_PUT    (msg, NL80211_ATTR_FRAME,
                (int)(IEEE80211_HDR_LEN + body_len), frame);
    /* Use offchannel? No - on-channel for assoc'd frames. */
    return nl_send_msg(c->nl_cmd, msg);
nla_put_failure:
    nlmsg_free(msg); return -EMSGSIZE;
}

/* ---- supplicant callbacks ---- */

static int supp_send_auth_frame_cb(void *ctx,
                                   const uint8_t *frame, size_t len)
{
    struct test_ctx *c = (struct test_ctx *)ctx;
    printf("[supp -> nl80211] auth frame body %zuB\n", len);
    return send_mgmt_auth(c, frame, len);
}

static int supp_send_eapol_cb(void *ctx, const uint8_t *frame, size_t len)
{
    struct test_ctx *c = (struct test_ctx *)ctx;
    uint8_t  eth[1600];
    struct sockaddr_ll sll;
    if (len + 14 > sizeof(eth)) return -1;
    memcpy(&eth[0], c->bssid,   6);
    memcpy(&eth[6], c->sta_mac, 6);
    eth[12] = (uint8_t)(EAPOL_ETH_TYPE >> 8);
    eth[13] = (uint8_t)(EAPOL_ETH_TYPE & 0xFFU);
    memcpy(&eth[14], frame, len);
    memset(&sll, 0, sizeof(sll));
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = c->ifindex;
    sll.sll_halen   = 6;
    memcpy(sll.sll_addr, c->bssid, 6);
    if (sendto(c->packet_sock, eth, len + 14, 0,
               (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto eapol"); return -1;
    }
    return 0;
}

static int supp_install_key_cb(void *ctx, wolfip_supplicant_keytype_t kt,
                               uint8_t idx, const uint8_t *k, size_t l)
{
    (void)ctx; (void)kt; (void)idx; (void)k; (void)l;
    return 0;
}

/* ---- nl80211 event callback ---- */

static int event_cb(struct nl_msg *msg, void *arg)
{
    struct test_ctx   *c   = (struct test_ctx *)arg;
    struct nlmsghdr   *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    struct nlattr     *attrs[NL80211_ATTR_MAX + 1];

    nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    switch (gnlh->cmd) {
    case NL80211_CMD_EXTERNAL_AUTH: {
        uint32_t action = NL80211_EXTERNAL_AUTH_START;
        if (attrs[NL80211_ATTR_EXTERNAL_AUTH_ACTION]) {
            action = nla_get_u32(attrs[NL80211_ATTR_EXTERNAL_AUTH_ACTION]);
        }
        if (attrs[NL80211_ATTR_BSSID]) {
            memcpy(c->bssid, nla_data(attrs[NL80211_ATTR_BSSID]), 6);
        }
        printf("[nl80211] EXTERNAL_AUTH action=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
               action,
               c->bssid[0],c->bssid[1],c->bssid[2],
               c->bssid[3],c->bssid[4],c->bssid[5]);
        if (action == NL80211_EXTERNAL_AUTH_START && !c->sae_started) {
            c->sae_started = 1;
            if (wolfip_supplicant_kick(c->supp, now_ms()) != 0) {
                fprintf(stderr, "supplicant kick failed\n");
                c->failed = 1;
            }
        }
        return NL_SKIP;
    }
    case NL80211_CMD_FRAME: {
        const uint8_t *fr;
        int            fr_len;
        if (!attrs[NL80211_ATTR_FRAME]) return NL_SKIP;
        fr     = nla_data(attrs[NL80211_ATTR_FRAME]);
        fr_len = nla_len(attrs[NL80211_ATTR_FRAME]);
        if (fr_len <= IEEE80211_HDR_LEN) return NL_SKIP;
        /* fc[0] = 0xB0 (Auth subtype). Body starts after 24-byte hdr. */
        if (fr[0] != 0xB0) return NL_SKIP;
        printf("[nl80211 -> supp] auth frame body %dB\n",
               fr_len - IEEE80211_HDR_LEN);
        wolfip_supplicant_rx_auth_frame(c->supp,
                                        fr + IEEE80211_HDR_LEN,
                                        (size_t)(fr_len - IEEE80211_HDR_LEN),
                                        now_ms());
        if (wolfip_supplicant_state(c->supp) == SUPP_STATE_4WAY_M1_WAIT) {
            /* SAE done - acknowledge to kernel so it proceeds to assoc. */
            printf("[supp] SAE done; sending EXTERNAL_AUTH success\n");
            do_external_auth_result(c, 0, "");
        }
        return NL_SKIP;
    }
    case NL80211_CMD_CONNECT: {
        uint16_t st = 0xFFFF;
        if (attrs[NL80211_ATTR_STATUS_CODE]) {
            st = nla_get_u16(attrs[NL80211_ATTR_STATUS_CODE]);
        }
        printf("[nl80211] CMD_CONNECT status=%u\n", st);
        if (st == 0) c->kernel_connected = 1;
        else c->failed = 1;
        return NL_SKIP;
    }
    case NL80211_CMD_DISCONNECT:
        printf("[nl80211] DISCONNECT\n");
        c->failed = 1;
        return NL_STOP;
    default:
        printf("[nl80211] event cmd=%u\n", gnlh->cmd);
        return NL_SKIP;
    }
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "wlan1";
    const char *ssid   = (argc > 2) ? argv[2] : "wolfIP-SAE";
    const char *pw     = (argc > 3) ? argv[3] : "ThisIsAPassword!";
    const char *bssid  = (argc > 4) ? argv[4] : "02:00:00:00:00:00";
    uint32_t    freq   = (argc > 5) ? (uint32_t)atoi(argv[5]) : 2412;
    struct wolfip_supplicant_cfg cfg;
    int    mlme_group;
    uint64_t deadline;
    unsigned int b[6];
    int    i;
    struct nl_cb *cb;
    int    nl_fd, pk_fd;
#if defined(WOLFIP_ENABLE_SAE_H2E) && WOLFIP_ENABLE_SAE_H2E
    const char *h2e_env;
#endif

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    memset(&CTX, 0, sizeof(CTX));
    strncpy(CTX.ifname, ifname, sizeof(CTX.ifname) - 1);
    if (sscanf(bssid, "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) != 6) {
        fprintf(stderr, "bad bssid: %s\n", bssid); return 2;
    }
    for (i = 0; i < 6; i++) CTX.bssid[i] = (uint8_t)b[i];
    if (packet_open(ifname, &CTX) != 0) return 1;
    printf("[init] iface=%s ifindex=%d sta_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           ifname, CTX.ifindex,
           CTX.sta_mac[0], CTX.sta_mac[1], CTX.sta_mac[2],
           CTX.sta_mac[3], CTX.sta_mac[4], CTX.sta_mac[5]);

    CTX.nl_cmd   = nl_socket_alloc();
    CTX.nl_event = nl_socket_alloc();
    if (!CTX.nl_cmd || !CTX.nl_event) {
        fprintf(stderr, "nl_socket_alloc\n"); return 1;
    }
    if (genl_connect(CTX.nl_cmd) < 0 || genl_connect(CTX.nl_event) < 0) {
        fprintf(stderr, "genl_connect\n"); return 1;
    }
    CTX.nl_family = genl_ctrl_resolve(CTX.nl_cmd, "nl80211");
    if (CTX.nl_family < 0) { fprintf(stderr, "no nl80211\n"); return 1; }
    mlme_group = genl_ctrl_resolve_grp(CTX.nl_event, "nl80211", "mlme");
    if (mlme_group < 0) { fprintf(stderr, "no mlme grp\n"); return 1; }
    nl_socket_add_membership(CTX.nl_event, mlme_group);
    nl_socket_disable_seq_check(CTX.nl_event);

    /* With NL80211_ATTR_EXTERNAL_AUTH_SUPPORT set in the CONNECT
     * command, the kernel handles auth-frame relay automatically via
     * NL80211_CMD_FRAME events on the same socket that listens for
     * NL80211_CMD_EXTERNAL_AUTH. Manual REGISTER_FRAME is unnecessary
     * (and rejected with EINVAL by mainline kernels for the Auth
     * subtype when the wdev is about to do external auth). */
    (void)register_auth_frames;
    printf("[init] external-auth mode (no manual REGISTER_FRAME)\n");

    /* Set up supplicant. WOLFIP_SAE_H2E=1 in the env switches the
     * supplicant to RFC 9380 Hash-to-Element PWE (status code 126 in
     * Commit) for interop against hostapd configured with sae_pwe=2. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = ssid; cfg.ssid_len = strlen(ssid);
    cfg.auth_mode      = WOLFIP_AUTH_SAE;
    cfg.passphrase     = pw;
    cfg.passphrase_len = strlen(pw);
    cfg.sae_group      = SAE_GROUP_19;
#if defined(WOLFIP_ENABLE_SAE_H2E) && WOLFIP_ENABLE_SAE_H2E
    h2e_env = getenv("WOLFIP_SAE_H2E");
    cfg.sae_h2e = (h2e_env != NULL && h2e_env[0] == '1') ? 1 : 0;
#endif
    memcpy(cfg.ap_mac,  CTX.bssid,   6);
    memcpy(cfg.sta_mac, CTX.sta_mac, 6);
    cfg.ops.send_eapol      = supp_send_eapol_cb;
    cfg.ops.install_key     = supp_install_key_cb;
    cfg.ops.send_auth_frame = supp_send_auth_frame_cb;
    cfg.ops.ctx             = &CTX;

    CTX.supp = wolfip_supplicant_new(&cfg);
    if (!CTX.supp) { fprintf(stderr, "supplicant_new\n"); return 1; }
    printf("[init] supplicant ready (SAE, P-256, %s)\n",
           cfg.sae_h2e ? "H2E" : "H&P");

    if (do_connect_sae(&CTX, ssid, freq) != 0) {
        fprintf(stderr, "CONNECT failed\n"); return 1;
    }
    printf("[init] CONNECT submitted ssid='%s' freq=%uMHz\n", ssid, freq);

    /* Event loop: pump nl80211 events + AF_PACKET frames. */
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    nl_fd = nl_socket_get_fd(CTX.nl_event);
    pk_fd = CTX.packet_sock;
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_cb, &CTX);

    deadline = now_ms() + 20000;
    while (now_ms() < deadline && !g_stop && !CTX.failed) {
        struct timeval tv = {0, 200000};
        fd_set rfds;
        int    sel;
        int    max_fd = nl_fd > pk_fd ? nl_fd : pk_fd;
        FD_ZERO(&rfds);
        FD_SET(nl_fd, &rfds);
        FD_SET(pk_fd, &rfds);
        sel = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (sel > 0) {
            if (FD_ISSET(nl_fd, &rfds)) {
                nl_recvmsgs(CTX.nl_event, cb);
            }
            if (FD_ISSET(pk_fd, &rfds)) {
                uint8_t buf[1600];
                ssize_t n = recv(pk_fd, buf, sizeof(buf), 0);
                if (n >= 14
                    && memcmp(&buf[6], CTX.sta_mac, 6) != 0) {
                    wolfip_supplicant_rx(CTX.supp, buf + 14,
                                         (size_t)(n - 14), now_ms());
                }
            }
        }
        wolfip_supplicant_tick(CTX.supp, now_ms());
        if (wolfip_supplicant_state(CTX.supp) == SUPP_STATE_AUTHENTICATED) {
            CTX.done = 1;
            break;
        }
    }
    nl_cb_put(cb);
    printf("[final] supp_state=%d kernel_connected=%d done=%d failed=%d\n",
           (int)wolfip_supplicant_state(CTX.supp),
           CTX.kernel_connected, CTX.done, CTX.failed);
    if (!CTX.done && !CTX.sae_started) {
        printf("[note] kernel never fired NL80211_CMD_EXTERNAL_AUTH.\n");
        printf("[note] If this is mac80211_hwsim, that is expected -\n");
        printf("[note] hwsim is SoftMAC and only supports SAE via the\n");
        printf("[note] AUTHENTICATE command path, not CONNECT+ExtAuth.\n");
        printf("[note] CYW43439 (FullMAC, brcmfmac) honors this path.\n");
    }

    wolfip_supplicant_free(CTX.supp);
    nl_socket_free(CTX.nl_event);
    nl_socket_free(CTX.nl_cmd);
    close(CTX.packet_sock);
    return CTX.done ? 0 : 1;
}

#else  /* !WOLFIP_ENABLE_SAE */

int main(void)
{
    printf("SAE not built (WOLFIP_ENABLE_SAE=0)\n");
    return 0;
}

#endif
