#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#ifndef CONFIG_IPFILTER
#define CONFIG_IPFILTER 0
#endif

#define ETHERNET
#define LINK_MTU 1536

#define MAX_TCPSOCKETS 4
#define MAX_UDPSOCKETS 2
#define MAX_ICMPSOCKETS 2
#define RXBUF_SIZE (20 * 1024)
#define TXBUF_SIZE (32 * 1024)

#ifndef WOLFIP_POSIX_TCPDUMP
#define WOLFIP_POSIX_TCPDUMP 0
#endif

/* POSIX Network Device Selection */
#ifndef WOLFIP_USE_VDE
#define WOLFIP_USE_VDE 0  /* 0 = TAP device (default), 1 = VDE */
#endif

#define MAX_NEIGHBORS 16

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 2
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 0
#endif

#ifndef WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_ENABLE_LOOPBACK 0
#endif

#if WOLFIP_ENABLE_LOOPBACK && WOLFIP_MAX_INTERFACES < 2
#error "WOLFIP_ENABLE_LOOPBACK requires WOLFIP_MAX_INTERFACES > 1"
#endif

/* Linux test configuration */
#define WOLFIP_IP "10.10.10.2"
#define HOST_STACK_IP "10.10.10.1"
#define WOLFIP_STATIC_DNS_IP "9.9.9.9"

#endif
