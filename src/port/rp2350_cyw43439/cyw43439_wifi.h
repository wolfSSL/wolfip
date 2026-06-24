/* cyw43439_wifi.h - wolfIP_wifi_ops adaptor for CYW43439
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef WOLFIP_CYW43439_WIFI_H
#define WOLFIP_CYW43439_WIFI_H

#include "wolfip.h"
#include "cyw43439_driver.h"  /* cyw43_eapol_cb_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Populate an ll_dev with the CYW43439 send/poll callbacks and
 * wifi_ops vtable. Reads the radio's MAC into ll->mac. Returns 0 on
 * success - the caller must have already brought the radio up via
 * cyw43_init() + cyw43_wifi_up(). */
int cyw43_wifi_attach(struct wolfIP_ll_dev *ll);

/* Redirect inbound EAPOL (0x888E) to the host supplicant's callback
 * while leaving 802.3 data on the wolfIP path. Call after attach once
 * the supplicant context exists. */
void cyw43_wifi_route_eapol(cyw43_eapol_cb_t eapol_cb, void *ctx);

extern const struct wolfIP_wifi_ops cyw43_wifi_ops;

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_CYW43439_WIFI_H */
