/* wg_allowedips.c
 *
 * wolfGuard allowed IPs lookup (flat table with longest prefix match)
 *
 * For embedded targets with small peer counts, a flat table with linear
 * scan should be sufficient.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/*
 * Compute network mask from CIDR prefix length
 * */

static uint32_t cidr_to_mask(uint8_t cidr)
{
    if (cidr == 0)
        return 0;
    if (cidr >= 32)
        return 0xFFFFFFFF;
    return ee32(~((1U << (32 - cidr)) - 1));
}

/*
 * Insert an allowed IP entry
 * */

int wg_allowedips_insert(struct wg_device *dev, uint32_t ip, uint8_t cidr,
                         uint8_t peer_idx)
{
    int i;
    uint32_t mask = cidr_to_mask(cidr);
    uint32_t masked_ip = ip & mask;

    /* Check for duplicate */
    for (i = 0; i < WOLFGUARD_MAX_ALLOWED_IPS; i++) {
        if (dev->allowed_ips[i].in_use &&
            dev->allowed_ips[i].ip == masked_ip &&
            dev->allowed_ips[i].cidr == cidr) {
            /* Update existing entry */
            dev->allowed_ips[i].peer_idx = peer_idx;
            return 0;
        }
    }

    /* Find free slot */
    for (i = 0; i < WOLFGUARD_MAX_ALLOWED_IPS; i++) {
        if (!dev->allowed_ips[i].in_use) {
            dev->allowed_ips[i].ip = masked_ip;
            dev->allowed_ips[i].cidr = cidr;
            dev->allowed_ips[i].peer_idx = peer_idx;
            dev->allowed_ips[i].in_use = 1;
            return 0;
        }
    }

    return -1; /* Table full */
}

/*
 * Lookup: find peer for a given destination IP (longest prefix match)
 *
 * Returns peer_idx or -1 if no match.
 * */

int wg_allowedips_lookup(struct wg_device *dev, uint32_t ip)
{
    int i;
    int best_idx = -1;
    uint8_t best_cidr = 0;

    for (i = 0; i < WOLFGUARD_MAX_ALLOWED_IPS; i++) {
        uint32_t mask;
        if (!dev->allowed_ips[i].in_use)
            continue;

        mask = cidr_to_mask(dev->allowed_ips[i].cidr);
        if ((ip & mask) == dev->allowed_ips[i].ip) {
            if (best_idx < 0 || dev->allowed_ips[i].cidr > best_cidr) {
                best_idx = dev->allowed_ips[i].peer_idx;
                best_cidr = dev->allowed_ips[i].cidr;
            }
        }
    }

    return best_idx;
}

/*
 * Remove all entries for a given peer
 * */

void wg_allowedips_remove_by_peer(struct wg_device *dev, uint8_t peer_idx)
{
    int i;

    for (i = 0; i < WOLFGUARD_MAX_ALLOWED_IPS; i++) {
        if (dev->allowed_ips[i].in_use &&
            dev->allowed_ips[i].peer_idx == peer_idx) {
            memset(&dev->allowed_ips[i], 0, sizeof(dev->allowed_ips[i]));
        }
    }
}

#endif /* WOLFGUARD */
