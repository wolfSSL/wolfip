/* wolfguard.c
 *
 * wolfGuard device init, public API, and wolfIP integration
 *
 * This module:
 * - Creates the wg0 virtual L3 interface (non_ethernet=1)
 * - Binds a UDP socket for outer WireGuard transport
 * - Routes incoming WG messages to the packet processor
 * - Routes outgoing plaintext from wg0 through encryption
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/*
 * Internal RX FIFO for decrypted packets injected into wg0
 *
 * wg_packet_receive() decrypts data and calls wolfIP_recv_ex()
 * directly, so no separate FIFO is needed for RX.
 *
 * The wg0 interface's poll callback returns 0 (no spontaneous data)
 * because all RX injection is push-based via wolfIP_recv_ex().
 * */

/* wg0 virtual interface callbacks */

static int wolfguard_ll_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    /* RX is push-based via wolfIP_recv_ex(), nothing to poll
     * this is defined pretty much because wolfip_ll_dev requires
     * a .poll function pointer. wolfip basically calls .poll() on
     * every interface during the wolfip_poll(), to check if the
     * interface has sponstaneous data to inject, which makes sense
     * if you are doing everything at level 2, because it's where
     * you would read your data. but wireguard/wolfguard operates
     * at level 3 entirely, which means all RX is technically
     * push-based via wolfip_recv_ex when a UDP packet arrives
     * and gets decrypted. The callback still needs to be
     * provided, because wolfip will call it unconditionally anyway.
     * */
    (void)ll;
    (void)buf;
    (void)len;
    return 0;
}

static int wolfguard_ll_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    /* This is called when wolfIP routes a packet out through wg0.
     * We need to find the device from the ll_dev pointer and encrypt. */
    struct wg_device *dev = (struct wg_device *)ll->priv;

    if (dev == NULL)
        return -1;

    return wolfguard_output(dev, (const uint8_t *)buf, len);
}

/* UDP socket callback for incoming WireGuard messages */

static void wg_udp_callback(int sock_fd, uint16_t events, void *arg)
{
    struct wg_device *dev = (struct wg_device *)arg;
    uint8_t buf[LINK_MTU + 128];
    struct wolfIP_sockaddr_in src;
    socklen_t src_len;
    int n;

    (void)sock_fd;

    if (!(events & CB_EVENT_READABLE))
        return;

    /* drain all available packets, wolfIP may batch multiple frames into
     * the socket RX FIFO during a single poll cycle, but the callback is
     * only invoked once.  Reading just one packet would leave stale
     * messages in the FIFO that corrupt later handshakes. */
    do {
        src_len = sizeof(src);
        n = wolfIP_sock_recvfrom(dev->stack, dev->udp_sock_fd,
                                 buf, sizeof(buf), 0,
                                 (struct wolfIP_sockaddr *)&src, &src_len);
        if (n <= 0)
            break;

        wg_packet_receive(dev, buf, (size_t)n,
                          src.sin_addr.s_addr, src.sin_port);
    } while (1);
}

/*
 * Public API
 * */

int wolfguard_init(struct wg_device *dev, struct wolfIP *stack,
                   unsigned int wg_if_idx, uint16_t listen_port)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in bind_addr;
    int ret;

    memset(dev, 0, sizeof(*dev));
    dev->stack = stack;
    dev->wg_if_idx = wg_if_idx;
    dev->listen_port = listen_port;

    /* Initialize RNG */
#ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
#endif
    ret = wc_InitRng(&dev->rng);
    if (ret != 0)
        return -1;

    /* Configure wg0 virtual interface */
    ll = wolfIP_getdev_ex(stack, wg_if_idx);
    if (ll == NULL) {
        wc_FreeRng(&dev->rng);
        return -1;
    }

    ll->non_ethernet = 1;
    ll->poll = wolfguard_ll_poll;
    ll->send = wolfguard_ll_send;
    ll->priv = dev;
    strncpy(ll->ifname, "wg0", sizeof(ll->ifname) - 1);

    /* Set wg0 MTU = outer MTU - 60 (IP + UDP + WG header overhead) */
    wolfIP_mtu_set(stack, wg_if_idx, LINK_MTU - 60);

    /* Create UDP socket for outer transport */
    dev->udp_sock_fd = wolfIP_sock_socket(stack, AF_INET, SOCK_DGRAM, 0);
    if (dev->udp_sock_fd < 0) {
        wc_FreeRng(&dev->rng);
        return -1;
    }

    /* Bind to listen port */
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(listen_port);
    bind_addr.sin_addr.s_addr = 0; /* INADDR_ANY */

    ret = wolfIP_sock_bind(stack, dev->udp_sock_fd,
                           (struct wolfIP_sockaddr *)&bind_addr,
                           sizeof(bind_addr));
    if (ret < 0) {
        wolfIP_sock_close(stack, dev->udp_sock_fd);
        wc_FreeRng(&dev->rng);
        return -1;
    }

    /* Register callback for incoming WG messages */
    wolfIP_register_callback(stack, dev->udp_sock_fd, wg_udp_callback, dev);

    return 0;
}

int wolfguard_set_private_key(struct wg_device *dev,
                              const uint8_t *private_key)
{
    int ret;

    memcpy(dev->static_private, private_key, WG_PRIVATE_KEY_LEN);

    ret = wg_pubkey_from_private(dev->static_public, dev->static_private);
    if (ret != 0) {
        wg_memzero(dev->static_private, WG_PRIVATE_KEY_LEN);
        return -1;
    }

    /* Re-initialize cookie checker with new public key */
    wg_cookie_checker_init(&dev->cookie_checker, dev->static_public);

    return 0;
}

int wolfguard_add_peer(struct wg_device *dev,
                       const uint8_t *public_key,
                       const uint8_t *preshared_key,
                       uint32_t endpoint_ip, uint16_t endpoint_port,
                       uint16_t persistent_keepalive)
{
    struct wg_peer *peer;
    int i;

    /* Find free slot */
    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        if (!dev->peers[i].is_active) {
            peer = &dev->peers[i];
            break;
        }
    }
    if (i >= WOLFGUARD_MAX_PEERS)
        return -1;

    memset(peer, 0, sizeof(*peer));
    memcpy(peer->public_key, public_key, WG_PUBLIC_KEY_LEN);
    peer->endpoint_ip = endpoint_ip;
    peer->endpoint_port = endpoint_port;
    peer->persistent_keepalive_interval = persistent_keepalive;
    peer->is_active = 1;

    /* Initialize handshake with pre-computed static-static DH */
    wg_noise_handshake_init(&peer->handshake, dev->static_private,
                            public_key, preshared_key, &dev->rng);

    /* Initialize cookie keys from peer's public key */
    wg_cookie_init(&peer->cookie, public_key);

    dev->num_peers++;
    return i;
}

int wolfguard_add_allowed_ip(struct wg_device *dev, int peer_idx,
                             uint32_t ip, uint8_t cidr)
{
    if (peer_idx < 0 || peer_idx >= WOLFGUARD_MAX_PEERS)
        return -1;
    if (!dev->peers[peer_idx].is_active)
        return -1;

    return wg_allowedips_insert(dev, ip, cidr, (uint8_t)peer_idx);
}

/*
 * TX callback: called when wg0 interface has a packet to send
 *
 * Looks up the destination IP in the allowed-IPs table to find
 * the peer, then encrypts and sends.
 * */

int wolfguard_output(struct wg_device *dev, const uint8_t *packet, size_t len)
{
    uint32_t dst_ip;
    int peer_idx;

    if (len < 20)
        return -1; /* Too short for IPv4 header */

    /* Extract destination IP from IPv4 header (offset 16) */
    memcpy(&dst_ip, packet + 16, 4);

    /* Look up peer by destination IP */
    peer_idx = wg_allowedips_lookup(dev, dst_ip);
    if (peer_idx < 0 || peer_idx >= WOLFGUARD_MAX_PEERS)
        return -1;

    if (!dev->peers[peer_idx].is_active)
        return -1;

    return wg_packet_send(dev, &dev->peers[peer_idx], packet, len);
}

/*
 * Main poll function, call from wolfIP_poll() loop
 * */

void wolfguard_poll(struct wg_device *dev, uint64_t now_ms)
{
    dev->now = now_ms;
    dev->under_load = (dev->handshakes_per_cycle > WOLFGUARD_MAX_PEERS);
    dev->handshakes_per_cycle = 0;
    wg_timers_tick(dev, now_ms);
}

/*
 * Cleanup
 * */

void wolfguard_destroy(struct wg_device *dev)
{
    int i;

    /* Zero all key material */
    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        if (dev->peers[i].is_active) {
            wg_memzero(&dev->peers[i].handshake,
                              sizeof(dev->peers[i].handshake));
            wg_memzero(&dev->peers[i].keypairs,
                              sizeof(dev->peers[i].keypairs));
            wg_memzero(&dev->peers[i].cookie,
                              sizeof(dev->peers[i].cookie));
            wg_memzero(&dev->peers[i].staged_packets,
                              sizeof(dev->peers[i].staged_packets));
            wg_memzero(&dev->peers[i].staged_packet_lens,
                              sizeof(dev->peers[i].staged_packet_lens));
        }
    }

    wg_memzero(dev->static_private, WG_PRIVATE_KEY_LEN);
    wg_memzero(&dev->cookie_checker, sizeof(dev->cookie_checker));

    if (dev->udp_sock_fd >= 0)
        wolfIP_sock_close(dev->stack, dev->udp_sock_fd);

    wc_FreeRng(&dev->rng);
}

#endif /* WOLFGUARD */
