/* nl80211_connect.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Minimal nl80211 client that drives a Linux mac80211 station radio
 * (typically a mac80211_hwsim virtual radio) through open auth + WPA2
 * association to a given AP. EAPOL frames are handled externally via
 * the netdev's AF_PACKET path (CONTROL_PORT semantics) so the wolfIP
 * supplicant can perform the 4-way handshake itself.
 *
 * Usage:
 *   nl80211_connect <ifname> <ssid> <ap_mac>
 *
 * Stays running once associated (the connection state lives in the
 * kernel for the lifetime of the netlink socket). Exits on SIGTERM /
 * SIGINT and tears the link down.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#define WPA_CIPHER_CCMP 0x000FAC04U   /* OUI 00:0F:AC suite 4 */
#define WPA_AKM_PSK     0x000FAC02U   /* OUI 00:0F:AC suite 2 */

/* Fixed RSN IE for WPA2-Personal (CCMP-128 group + pairwise, PSK AKM).
 * Element ID 0x30, length 0x14 (20 body bytes). Multi-byte values are
 * little-endian per IEEE 802.11 IE conventions.
 *
 * The kernel does not synthesize this from the WPA_VERSIONS / AKM /
 * CIPHER attrs alone - wpa_supplicant always provides the assembled
 * RSN IE via NL80211_ATTR_IE, and hostapd rejects an association
 * request whose RSN IE is missing or doesn't match the negotiated
 * cipher suite. */
static const uint8_t WPA2_PSK_RSN_IE[] = {
    0x30, 0x14,                 /* element id, length */
    0x01, 0x00,                 /* version 1 */
    0x00, 0x0F, 0xAC, 0x04,     /* group cipher CCMP-128 */
    0x01, 0x00,                 /* pairwise count = 1 */
    0x00, 0x0F, 0xAC, 0x04,     /* pairwise CCMP-128 */
    0x01, 0x00,                 /* AKM count = 1 */
    0x00, 0x0F, 0xAC, 0x02,     /* AKM PSK */
    0x00, 0x00                  /* RSN capabilities */
};

static volatile sig_atomic_t g_stop = 0;
static int  g_ifindex = -1;
static int  g_family  = -1;
static struct nl_sock *g_sk = NULL;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* Standard nl80211 ack/error/finish callbacks for blocking-ish use. */
static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
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

static int send_and_wait(struct nl_sock *sk, struct nl_msg *msg)
{
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    int err = 1;
    int ret;

    if (!cb) { nlmsg_free(msg); return -ENOMEM; }
    ret = nl_send_auto(sk, msg);
    if (ret < 0) { nlmsg_free(msg); nl_cb_put(cb); return ret; }

    nl_cb_err(cb, NL_CB_CUSTOM, err_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK,    NL_CB_CUSTOM, ack_handler,    &err);

    while (err > 0) {
        nl_recvmsgs(sk, cb);
    }
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}

static int do_connect(struct nl_sock *sk, int family, int ifindex,
                      const char *ssid, const uint8_t bssid[6],
                      uint32_t freq_mhz)
{
    struct nl_msg *msg = nlmsg_alloc();
    uint32_t pair[1] = { WPA_CIPHER_CCMP };
    uint32_t akm[1]  = { WPA_AKM_PSK };

    if (!msg) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
                NL80211_CMD_CONNECT, 0);
    NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, ifindex);
    NLA_PUT     (msg, NL80211_ATTR_SSID, (int)strlen(ssid), ssid);
    NLA_PUT_U32 (msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    NLA_PUT_FLAG(msg, NL80211_ATTR_PRIVACY);
    NLA_PUT_U32 (msg, NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2);
    NLA_PUT     (msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                 (int)sizeof(pair), pair);
    NLA_PUT_U32 (msg, NL80211_ATTR_CIPHER_SUITE_GROUP, WPA_CIPHER_CCMP);
    NLA_PUT     (msg, NL80211_ATTR_AKM_SUITES, (int)sizeof(akm), akm);
    /* CONTROL_PORT: kernel forwards EAPOL frames via the netdev as
     * unencrypted Ethernet, our supplicant handles them via AF_PACKET. */
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT);
    NLA_PUT_U16 (msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, 0x888E);
    NLA_PUT_FLAG(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    /* Pin the channel so the kernel skips scanning. mac80211_hwsim's
     * default reg domain blocks active scan on some channels; using
     * WIPHY_FREQ as a hint with a known BSSID lets connect go directly
     * to auth+assoc on the matching frequency. */
    NLA_PUT_U32 (msg, NL80211_ATTR_WIPHY_FREQ, freq_mhz);
    /* Assoc-request IE blob: the RSN IE must appear here so hostapd
     * accepts the association. */
    NLA_PUT     (msg, NL80211_ATTR_IE,
                 (int)sizeof(WPA2_PSK_RSN_IE), WPA2_PSK_RSN_IE);
    if (bssid) {
        NLA_PUT(msg, NL80211_ATTR_MAC, 6, bssid);
    }
    return send_and_wait(sk, msg);

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

static int do_disconnect(struct nl_sock *sk, int family, int ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
                NL80211_CMD_DISCONNECT, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    return send_and_wait(sk, msg);
nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned int v[6];
    int i;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (i = 0; i < 6; i++) {
        if (v[i] > 0xFF) return -1;
        out[i] = (uint8_t)v[i];
    }
    return 0;
}

/* Inspect inbound nl80211 multicast events on a second socket. We use
 * this to surface the real connect outcome (success / status code from
 * the AP) instead of blindly trusting that the kernel accepted CONNECT. */
static int event_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr   *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh;
    struct nlattr     *attrs[NL80211_ATTR_MAX + 1];
    int *got = (int *)arg;

    gnlh = nlmsg_data(nlh);
    nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);
    switch (gnlh->cmd) {
    case NL80211_CMD_CONNECT: {
        uint16_t status = 0xFFFF;
        if (attrs[NL80211_ATTR_STATUS_CODE]) {
            status = nla_get_u16(attrs[NL80211_ATTR_STATUS_CODE]);
        }
        printf("event: NL80211_CMD_CONNECT status=%u (%s)\n",
               status, status == 0 ? "SUCCESS" : "FAILURE");
        *got = (status == 0) ? 1 : 2;
        return NL_STOP;
    }
    case NL80211_CMD_DISCONNECT:
        printf("event: NL80211_CMD_DISCONNECT\n");
        *got = 3;
        return NL_STOP;
    default:
        break;
    }
    return NL_SKIP;
}

int main(int argc, char **argv)
{
    const char *ifname;
    const char *ssid;
    uint8_t bssid[6];
    uint32_t freq_mhz = 2412;
    int ifindex;
    int rc;
    struct nl_sock *event_sk = NULL;
    int   mlme_group;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 4 || argc > 5) {
        fprintf(stderr,
            "Usage: %s <ifname> <ssid> <ap_mac> [freq_mhz]\n", argv[0]);
        return 2;
    }
    ifname = argv[1]; ssid = argv[2];
    if (parse_mac(argv[3], bssid) != 0) {
        fprintf(stderr, "bad ap_mac: %s\n", argv[3]); return 2;
    }
    if (argc == 5) {
        freq_mhz = (uint32_t)strtoul(argv[4], NULL, 10);
    }
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", ifname, strerror(errno));
        return 1;
    }
    g_ifindex = ifindex;

    g_sk = nl_socket_alloc();
    if (!g_sk) { fprintf(stderr, "nl_socket_alloc\n"); return 1; }
    if (genl_connect(g_sk) < 0) {
        fprintf(stderr, "genl_connect\n"); return 1;
    }
    g_family = genl_ctrl_resolve(g_sk, "nl80211");
    if (g_family < 0) {
        fprintf(stderr, "nl80211 family not available\n"); return 1;
    }

    /* Subscribe to the "mlme" multicast group to receive CONNECT /
     * DISCONNECT events asynchronously. */
    event_sk = nl_socket_alloc();
    if (!event_sk) { fprintf(stderr, "event_sk alloc\n"); return 1; }
    if (genl_connect(event_sk) < 0) {
        fprintf(stderr, "event genl_connect\n"); return 1;
    }
    mlme_group = genl_ctrl_resolve_grp(event_sk, "nl80211", "mlme");
    if (mlme_group < 0) {
        fprintf(stderr, "resolve mlme group\n"); return 1;
    }
    nl_socket_add_membership(event_sk, mlme_group);
    nl_socket_disable_seq_check(event_sk);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("nl80211_connect: ssid='%s' bssid=%s freq=%uMHz ifname=%s ifindex=%d\n",
           ssid, argv[3], freq_mhz, ifname, ifindex);
    rc = do_connect(g_sk, g_family, ifindex, ssid, bssid, freq_mhz);
    if (rc != 0) {
        fprintf(stderr, "NL80211_CMD_CONNECT submit failed: %d (%s)\n",
                rc, strerror(-rc));
        nl_socket_free(event_sk);
        nl_socket_free(g_sk);
        return 1;
    }
    printf("nl80211_connect: CONNECT submitted; waiting for result event\n");

    /* Pump events for up to 5 seconds to surface the actual outcome. */
    {
        struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
        int got = 0;
        int fd = nl_socket_get_fd(event_sk);
        int waited_ms = 0;
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_cb, &got);
        while (got == 0 && waited_ms < 5000 && !g_stop) {
            struct timeval tv = {0, 100000};
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0
                && FD_ISSET(fd, &rfds)) {
                nl_recvmsgs(event_sk, cb);
            }
            waited_ms += 100;
        }
        nl_cb_put(cb);
        if (got == 0) {
            fprintf(stderr,
                    "no CONNECT/DISCONNECT event in 5s - kernel ignored?\n");
        }
    }

    /* Hold until SIGTERM regardless. Kernel maintains the assoc state
     * for the lifetime of g_sk. */
    while (!g_stop) {
        pause();
    }

    printf("nl80211_connect: disconnecting\n");
    do_disconnect(g_sk, g_family, ifindex);
    nl_socket_free(event_sk);
    nl_socket_free(g_sk);
    return 0;
}
