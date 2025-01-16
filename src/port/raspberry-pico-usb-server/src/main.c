/* main.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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
 * *****
 *
 * Based on LwIP drivers for TinyUSB,
 * Copyright (c) 2020 Peter Lawrence (MIT Licensed),
 * which was also influenced by lrndis https://github.com/fetisov/lrndis

   This appears as either a RNDIS or CDC-ECM USB virtual network adapter; the OS picks its preference

   RNDIS should be valid on Linux and Windows hosts, and CDC-ECM should be valid on Linux and macOS hosts

   The MCU appears to the host as IP address 192.168.7.1.

   Some smartphones *may* work with this implementation as well, but likely have limited (broken) drivers,
   and likely their manufacturer has not tested such functionality.  Some code workarounds could be tried:

   The smartphone may only have an ECM driver, but refuse to automatically pick ECM (unlike the OSes above);
   try modifying usb_descriptors.c so that CONFIG_ID_ECM is default.

   The smartphone may be artificially picky about which Ethernet MAC address to recognize; if this happens,
   try changing the first byte of tud_network_mac_address[] below from 0x02 to 0x00 (clearing bit 1).
*/

#include "bsp/board_api.h"
#include "tusb.h"
#include "config.h"
#include "wolfip.h"

extern char MOTD[];

/* Our globals */
static struct wolfIP *IPStack = NULL;

/* Two static buffers for RX frames from USB host */
uint8_t tusb_net_rxbuf[LINK_MTU][2];
uint8_t tusb_net_rxbuf_used[2] =  {0, 0};

/* Two static buffers for TX frames to USB host */
uint8_t tusb_net_txbuf[LINK_MTU][2];
uint16_t tusb_net_txbuf_sz[2] = {0, 0};

/* Fixed mac-address for the raspberry side of the link.
 * it is suggested that the first byte is 0x02 to indicate a link-local address
 */
uint8_t tud_network_mac_address[6] = {0x02, 0x02, 0x84, 0x6A, 0x96, 0x00};

/* wolfIP_getrandom is a frontend to the ADC-based random number generator.
 * See rand.c for more details.
 */
extern int custom_random_seed(unsigned char *seed, unsigned int size);
uint32_t wolfIP_getrandom(void)
{
    uint32_t seed;
    custom_random_seed((unsigned char *)&seed, 4);
    return seed;
}

/* ll_usb_send is the function that sends a frame to the USB host.
 * It is called by the wolfIP stack when a frame is ready to be sent.
 * It will return the number of bytes sent, or 0 if the USB host is not ready.
 */
static int ll_usb_send(struct ll *dev, void *frame, uint32_t sz) {
    uint16_t sz16 = (uint16_t)sz;
    uint32_t i;
    (void) dev;
    board_led_on();
    for (;;) {
        if (!tud_ready()) {
            return 0;
        }
        if (tud_network_can_xmit(sz16)) {
            for (i = 0; i < 2; i++) {
                if (tusb_net_txbuf_sz[i] == 0) {
                    memcpy(tusb_net_txbuf[i], frame, sz16);
                    tusb_net_txbuf_sz[i] = sz16;
                    tud_network_xmit(tusb_net_txbuf[i], tusb_net_txbuf_sz[i]);
                    board_led_on();
                    return (int)sz16;
                }
            }
            return 0;
        }
        /* transfer execution to TinyUSB in the hopes that it will finish transmitting the prior packet */
        tud_task();
    }
}

/* This is the callback that TinyUSB calls when it is ready to send a frame.
 * This is where the write operation is finalized.
 */
uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) {
    uint16_t ret = arg;
    (void) ref;
    (void) arg;
    memcpy(dst, ref, arg);
    if (ref == tusb_net_rxbuf[0])
        tusb_net_txbuf_sz[0] = 0;
    else if (ref == tusb_net_txbuf[1])
        tusb_net_txbuf_sz[1] = 0;
    board_led_off();
    return ret;
}

/* This is the callback that TinyUSB calls when it is ready to receive a frame.
 * This is where the read operation is initiated, the frame is copied to the
 * static buffer, and the buffer is marked as used.
 */

static void tusb_net_push_rx(const uint8_t *src, uint16_t size) {
    uint8_t *dst = NULL;
    int i;
    for (i = 0; i < 2; i++) {
        if (!tusb_net_rxbuf_used[i]) {
            dst = tusb_net_rxbuf[i];
            break;
        }
    }
    if (dst) {
        memcpy(dst, src, size);
        tusb_net_rxbuf_used[i] = 1;
        board_led_on();
    }
}

bool tud_network_recv_cb(const uint8_t *src, uint16_t size) {
    tusb_net_push_rx(src, size);
    return true;
}

/* This is the poll function of the wolfIP device driver.
 * It is called by the wolfIP stack when it is ready to receive a frame.
 * It will return the number of bytes received, or 0 if no frame is available.
 *
 * Frames copied in tusb_net_push_rx are processed here and sent to the stack.
 */
int  ll_usb_poll(struct ll *dev, void *frame, uint32_t sz) {
    int i;
    (void) dev;
    if (sz < 64)
        return 0;
    for (i = 0; i < 2; i++) {
        if (tusb_net_rxbuf_used[i]) {
            memcpy(frame, tusb_net_rxbuf[i], sz);
            tusb_net_rxbuf_used[i] = 0;
            board_led_off();
            return (int)sz;
        }
    }
    return 0;
}

void tud_network_init_cb(void)
{
}

/* Telnet server (telnetd) initialization */
static int tel_s = -1;
static int tel_c = -1;

static void telnet_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP_sockaddr_in addr;
    uint32_t socklen = sizeof(addr);
    (void)arg;
    if ((fd == tel_s) && (event & CB_EVENT_READABLE) && (tel_c == -1)) {
        char ipaddr[16];
        char welcome_msg[32];
        tel_c = wolfIP_sock_accept(IPStack, tel_s, (struct wolfIP_sockaddr*)&addr, &socklen);
        if (tel_c > 0) {
            iptoa(ee32(addr.sin_addr.s_addr), ipaddr);
            snprintf(welcome_msg, sizeof(welcome_msg), "Welcome %s!\n", ipaddr);
            wolfIP_sock_write(IPStack, tel_c, MOTD, strlen(MOTD));
            wolfIP_sock_write(IPStack, tel_c, welcome_msg, strlen(welcome_msg));
        }
    }
#if 0
    else if ((fd == tel_c) && (event & CB_EVENT_READABLE  )) {
        int ret;
        ret = wolfIP_sock_recv((struct wolfIP *)arg, tel_c, buf, sizeof(buf), 0);
        if (ret != -11) {
            if (ret < 0) {
                printf("Recv error: %d\n", ret);
                wolfIP_sock_close((struct wolfIP *)arg, tel_c);
            } else if (ret == 0) {
                printf("Client side closed the connection.\n");
                wolfIP_sock_close((struct wolfIP *)arg, tel_c);
                printf("Server: Exiting.\n");
                exit_ok = 1;
            } else if (ret > 0) {
                printf("recv: %d, echoing back\n", ret);
                tot_recv += ret;
            }
        }
    }
#endif
}


static void telnetd_init(void)
{
    struct wolfIP_sockaddr_in addr;
    if (tel_s < 0)
        tel_s = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, tel_s, telnet_cb, NULL);

    addr.sin_family = AF_INET;
    addr.sin_port = ee16(23);
    addr.sin_addr.s_addr = 0;

    wolfIP_sock_bind(IPStack, tel_s, (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    wolfIP_sock_listen(IPStack, tel_s, 1);
}

int main(void)
{
    struct ll *tusb_netdev;
    /* initialize TinyUSB */
    board_init();

    // init device stack on configured roothub port
    tud_init(BOARD_TUD_RHPORT);

    if (board_init_after_tusb) {
        board_init_after_tusb();
    }

    board_led_on();

    wolfIP_init_static(&IPStack);
    tusb_netdev = wolfIP_getdev(IPStack);
    memcpy(tusb_netdev->mac, tud_network_mac_address, 6);
    strcpy(tusb_netdev->ifname, "tusb");
    tusb_netdev->poll = ll_usb_poll;
    tusb_netdev->send = ll_usb_send;

    /* set the IP address, netmask, and gateway */
    /* 192.168.7.2/24, gateway 192.168.7.1 */
    wolfIP_ipconfig_set(IPStack, atoip4("192.168.7.2"),
            atoip4("255.255.255.0"), atoip4("192.168.7.1"));

    telnetd_init();

    board_led_off();
    while (1) {
        tud_task();
        wolfIP_poll(IPStack, board_millis());
    }
    return 0;
}
