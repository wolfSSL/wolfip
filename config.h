#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#define ETHERNET
#define LINK_MTU 1536

#define MAX_TCPSOCKETS 4
#define MAX_UDPSOCKETS 2
#define RXBUF_SIZE LINK_MTU * 16
#define TXBUF_SIZE LINK_MTU * 16

#define MAX_NEIGHBORS 16

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 1
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 0
#endif

/* Linux test configuration */
#define WOLFIP_IP "10.10.10.2"
#define LINUX_IP "10.10.10.1"

#endif
