#ifdef IP_MULTICAST

static void multicast_mreq(struct wolfIP_ip_mreq *mreq, ip4 group, ip4 if_addr)
{
    memset(mreq, 0, sizeof(*mreq));
    mreq->imr_multiaddr.s_addr = ee32(group);
    mreq->imr_interface.s_addr = ee32(if_addr);
}

static uint8_t *last_igmp_payload(void)
{
    return last_frame_sent + ETH_HEADER_LEN + IP_HEADER_LEN + IP_OPTION_ROUTER_ALERT_LEN;
}

static void build_multicast_udp(uint8_t *buf, struct wolfIP *s, ip4 src, ip4 dst,
                                uint16_t sport, uint16_t dport,
                                const void *payload, uint16_t payload_len)
{
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    uint8_t mac[6];

    memset(buf, 0, sizeof(struct wolfIP_udp_datagram) + payload_len);
    mcast_ip_to_eth(dst, mac);
    memcpy(udp->ip.eth.dst, mac, sizeof(mac));
    memcpy(udp->ip.eth.src, "\x02\x00\x00\x00\x00\x01", 6);
    udp->ip.eth.type = ee16(ETH_TYPE_IP);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + payload_len);
    udp->ip.src = ee32(src);
    udp->ip.dst = ee32(dst);
    udp->src_port = ee16(sport);
    udp->dst_port = ee16(dport);
    udp->len = ee16(UDP_HEADER_LEN + payload_len);
    memcpy(udp->data, payload, payload_len);
    (void)s;
    fix_udp_checksums(udp);
}

START_TEST(test_multicast_join_and_drop_reports)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_ip_mreq mreq;
    ip4 group = 0xE9010203U;
    uint8_t *igmp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000002U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    multicast_mreq(&mreq, group, IPADDR_ANY);
    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_uint_eq(s.mcast[0].group, group);
    ck_assert_uint_eq(s.mcast[0].refs, 1);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_mem_eq(last_frame_sent, "\x01\x00\x5e\x00\x00\x16", 6);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + 9], WI_IPPROTO_IGMP);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + 8], 1);
    igmp = last_igmp_payload();
    ck_assert_uint_eq(igmp[0], IGMP_TYPE_V3_MEMBERSHIP_REPORT);
    ck_assert_uint_eq(igmp[8], IGMPV3_REC_MODE_IS_EXCLUDE);
    ck_assert_uint_eq(get_be32(igmp + 12), group);

    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_uint_eq(s.mcast[0].refs, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    igmp = last_igmp_payload();
    ck_assert_uint_eq(igmp[8], IGMPV3_REC_CHANGE_TO_INCLUDE);
}
END_TEST

START_TEST(test_multicast_join_validation_and_shared_refs)
{
    struct wolfIP s;
    int sd1;
    int sd2;
    struct wolfIP_ip_mreq mreq;
    struct wolfIP_ip_mreq bad;
    ip4 group = 0xE9010204U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000002U, 0xFFFFFF00U, 0);
    sd1 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    sd2 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd1, 0);
    ck_assert_int_gt(sd2, 0);

    multicast_mreq(&bad, 0x0A000001U, IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd1, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &bad, sizeof(bad)), -WOLFIP_EINVAL);
    multicast_mreq(&mreq, group, IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd1, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd1, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd2, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_uint_eq(s.mcast[0].refs, 2);

    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd1, WOLFIP_SOL_IP,
            WOLFIP_IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_uint_eq(s.mcast[0].refs, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_eq(wolfIP_sock_close(&s, sd2), 0);
    ck_assert_uint_eq(s.mcast[0].refs, 0);
}
END_TEST

START_TEST(test_multicast_udp_receive_requires_join)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct wolfIP_ip_mreq mreq;
    uint8_t out[8];
    const char payload[] = "hello";
    uint8_t frame[sizeof(struct wolfIP_udp_datagram) + sizeof(payload)];
    ip4 group = 0xE9010205U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000002U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5000);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
            sizeof(sin)), 0);

    build_multicast_udp(frame, &s, 0x0A000001U, group, 4000, 5000,
                        payload, sizeof(payload));
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, sizeof(frame));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, out, sizeof(out), 0,
            (struct wolfIP_sockaddr *)&from, &fromlen), -WOLFIP_EAGAIN);

    multicast_mreq(&mreq, group, IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, sizeof(frame));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, out, sizeof(out), 0,
            (struct wolfIP_sockaddr *)&from, &fromlen), (int)sizeof(payload));
    ck_assert_mem_eq(out, payload, sizeof(payload));
}
END_TEST

START_TEST(test_multicast_udp_send_mac_ttl_loop_and_options)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in bind_addr;
    struct wolfIP_sockaddr_in dst;
    struct wolfIP_ip_mreq mreq;
    struct wolfIP_udp_datagram *udp;
    uint8_t out[8];
    int ttl = 7;
    int loop = 1;
    int got = 0;
    socklen_t gotlen = sizeof(got);
    ip4 group = 0xE9010206U;
    const char payload[] = "mc";

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000002U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(5001);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&bind_addr,
            sizeof(bind_addr)), 0);
    multicast_mreq(&mreq, group, IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &ttl, sizeof(ttl)), 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_LOOP, &loop, sizeof(loop)), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &got, &gotlen), 0);
    ck_assert_int_eq(got, ttl);

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(5001);
    dst.sin_addr.s_addr = ee32(group);
    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&dst, sizeof(dst)), (int)sizeof(payload));
    ck_assert_int_eq(wolfIP_poll(&s, 1), 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_mem_eq(last_frame_sent, "\x01\x00\x5e\x01\x02\x06", 6);
    udp = (struct wolfIP_udp_datagram *)last_frame_sent;
    ck_assert_uint_eq(udp->ip.ttl, ttl);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, out, sizeof(out), 0, NULL, NULL),
            (int)sizeof(payload));
    ck_assert_mem_eq(out, payload, sizeof(payload));
}
END_TEST

START_TEST(test_multicast_igmp_query_refreshes_report)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_ip_mreq mreq;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + IGMPV3_QUERY_MIN_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *igmp = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    ip4 group = 0xE9010207U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000002U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    multicast_mreq(&mreq, group, IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, "\x01\x00\x5e\x00\x00\x01", 6);
    memcpy(ip->eth.src, "\x02\x00\x00\x00\x00\x01", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl = 0x45;
    ip->ttl = 1;
    ip->proto = WI_IPPROTO_IGMP;
    ip->len = ee16(IP_HEADER_LEN + IGMPV3_QUERY_MIN_LEN);
    ip->src = ee32(0x0A000001U);
    ip->dst = ee32(IGMP_ALL_HOSTS);
    igmp[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
    put_be32(igmp + 4, group);
    put_be16(igmp + 2, ip_checksum_buf(igmp, IGMPV3_QUERY_MIN_LEN));
    fix_ip_checksum(ip);

    last_frame_sent_size = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, sizeof(frame));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_igmp_payload()[8], IGMPV3_REC_MODE_IS_EXCLUDE);
}
END_TEST

#endif /* IP_MULTICAST */
