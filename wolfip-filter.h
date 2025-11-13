#ifndef WOLFIP_FILTER_H
#define WOLFIP_FILTER_H

#include <stdint.h>

struct wolfIP;

enum wolfIP_filter_reason {
    WOLFIP_FILT_BINDING = 0,
    WOLFIP_FILT_DISSOCIATE = 1,
    WOLFIP_FILT_LISTENING = 2,
    WOLFIP_FILT_STOP_LISTENING = 3,
    WOLFIP_FILT_CONNECTING = 4,
    WOLFIP_FILT_ACCEPTING = 5,
    WOLFIP_FILT_CLOSED = 6,
    WOLFIP_FILT_REMOTE_RESET = 7,
    WOLFIP_FILT_RECEIVING = 8,
    WOLFIP_FILT_SENDING = 9,
    WOLFIP_FILT_ADDR_UNREACHABLE = 10,
    WOLFIP_FILT_PORT_UNREACHABLE = 11,
    WOLFIP_FILT_INBOUND_ERR = 12,
    WOLFIP_FILT_OUTBOUND_ERR = 13,
    WOLFIP_FILT_CLOSE_WAIT = 14
};

#define WOLFIP_FILT_MASK(reason) (1U << (reason))

#define WOLFIP_FILTER_PROTO_ETH  0x008f
#define WOLFIP_FILTER_PROTO_IP   0x0800
#define WOLFIP_FILTER_PROTO_TCP  0x0006
#define WOLFIP_FILTER_PROTO_UDP  0x0011
#define WOLFIP_FILTER_PROTO_ICMP 0x0001

struct wolfIP_filter_metadata {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t eth_type;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t ip_proto;
    union {
        struct {
            uint16_t src_port;
            uint16_t dst_port;
            uint8_t flags;
        } tcp;
        struct {
            uint16_t src_port;
            uint16_t dst_port;
        } udp;
        struct {
            uint8_t type;
            uint8_t code;
        } icmp;
    } l4;
};

struct wolfIP_filter_event {
    enum wolfIP_filter_reason reason;
    struct wolfIP *stack;
    unsigned int if_idx;
    uint32_t length;
    const void *buffer;
    struct wolfIP_filter_metadata meta;
};

typedef int (*wolfIP_filter_cb)(void *arg, const struct wolfIP_filter_event *event);

void wolfIP_filter_set_callback(wolfIP_filter_cb cb, void *arg);
void wolfIP_filter_set_mask(uint32_t mask);
void wolfIP_filter_set_eth_mask(uint32_t mask);
void wolfIP_filter_set_ip_mask(uint32_t mask);
void wolfIP_filter_set_tcp_mask(uint32_t mask);
void wolfIP_filter_set_udp_mask(uint32_t mask);
void wolfIP_filter_set_icmp_mask(uint32_t mask);
uint32_t wolfIP_filter_get_mask(void);

#endif /* WOLFIP_FILTER_H */
