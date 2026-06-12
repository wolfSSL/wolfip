/* app.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 *
 * Shared wolfIP UDP-echo + DHCP-client demo for the AMD/Xilinx ports
 * (ZynqMP / Versal / Zynq-7000). Board-specific bits (startup banner,
 * whether to unmask CPU IRQs) come from boards/<b>/board.c via app.h.
 */
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "board.h"
#include "uart.h"
#include "gic.h"
#include "gem.h"
#include "timer.h"
#include "app.h"

#define ECHO_PORT       7
#define RX_BUF_SIZE     1500

#ifdef SPEED_TEST
#define SPEED_PORT      9       /* discard/chargen-style TCP throughput port */
#endif

static struct wolfIP *IPStack;
#ifndef SPEED_TEST
static int udp_fd = -1;
static uint8_t udp_rx_buf[RX_BUF_SIZE];
#endif

/* Monotonic wall-clock milliseconds from the hardware timer. wolfIP needs a
 * real-millisecond tick for its DHCP/TCP/ARP timers; a free-running counter
 * (tick++) only approximates one and skews every timeout. timer_now() is a
 * raw up-counter at timer_freq() Hz. The seconds/remainder split avoids the
 * 64-bit overflow that a plain (ticks * 1000) would hit at long uptimes
 * (the remainder term stays below freq * 1000); it is exactly equal to
 * (ticks * 1000) / freq for all inputs. */
static uint64_t app_now_ms(void)
{
    uint64_t ticks = timer_now();
    uint64_t freq  = timer_freq();

    return (ticks / freq) * 1000ULL + ((ticks % freq) * 1000ULL) / freq;
}

/* Override newlib memset/memcpy with our own versions via linker --wrap.
 * The AArch64 newlib memset uses 'dc zva' which hangs on these bare-metal
 * setups; the ARMv7 override is kept defensively. The Makefile passes
 * -Wl,--wrap=memset -Wl,--wrap=memcpy.
 *
 * These do an 8-byte-at-a-time bulk loop with a bytewise tail (and never
 * use 'dc zva'). On the frame-staging hot path the buffers are 64-byte
 * aligned so the word loop is taken; the byte tail handles the rest. The
 * OCM is mapped Normal-NC (SCTLR.A=0), so the only requirement for the
 * 64-bit access is natural alignment, which the runtime check enforces. */
void *__wrap_memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    unsigned char  cb = (unsigned char)c;
    uint64_t w;

    if ((((uintptr_t)p) & 7u) == 0u) {
        w = (uint64_t)cb * 0x0101010101010101ULL;
        while (n >= 8u) {
            *(uint64_t *)p = w;
            p += 8;
            n -= 8u;
        }
    }
    while (n--)
        *p++ = cb;
    return s;
}

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    if (((((uintptr_t)d) | ((uintptr_t)s)) & 7u) == 0u) {
        while (n >= 8u) {
            *(uint64_t *)d = *(const uint64_t *)s;
            d += 8;
            s += 8;
            n -= 8u;
        }
    }
    while (n--)
        *d++ = *s++;
    return dest;
}

/* wolfIP needs a 32-bit random word for protocol identifiers (TCP ISN,
 * DHCP xid, DNS id, ephemeral source port, IP fragment id). We delegate
 * to the port-local memuse-pattern entropy source (entropy.c). */
extern uint32_t amd_get_random32(void);

uint32_t wolfIP_getrandom(void)
{
    return amd_get_random32();
}

#ifndef SPEED_TEST
static void udp_echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    struct wolfIP_sockaddr_in peer;
    uint32_t peer_len = sizeof(peer);
    int n;

    if (!(event & CB_EVENT_READABLE))
        return;

    n = wolfIP_sock_recvfrom(s, fd, udp_rx_buf, sizeof(udp_rx_buf), 0,
                             (struct wolfIP_sockaddr *)&peer, &peer_len);
    if (n > 0) {
        (void)wolfIP_sock_sendto(s, fd, udp_rx_buf, (uint32_t)n, 0,
                                 (struct wolfIP_sockaddr *)&peer, peer_len);
        uart_puts("UDP echo: "); uart_putdec((uint32_t)n);
        /* sin_addr.s_addr is network byte order (BSD convention); the
         * uart_putip4 helper, like atoip4/iptoa, expects host byte order
         * (first octet in the high byte), so swap before printing. */
        uart_puts(" bytes from "); uart_putip4(ee32(peer.sin_addr.s_addr));
        uart_puts("\n");
    }
}
#else /* SPEED_TEST */

/* TCP throughput server on SPEED_PORT (mirrors the va416xx SPEED_TEST harness).
 * One connection at a time: every byte the host sends is sunk (RX test) and,
 * whenever the socket is writable, a chargen-style buffer is pushed (TX test).
 * On close the totals and an average rate are printed. Measure from a host on
 * the same subnet:
 *   RX (board sinks):   dd if=/dev/zero bs=1460 count=N | nc <ip> 9
 *   TX (board sources): nc <ip> 9 </dev/null | pv -r >/dev/null
 */
static int      speed_listen_fd = -1;
static int      speed_client_fd = -1;
static uint64_t speed_rx_bytes;
static uint64_t speed_tx_bytes;
static uint64_t speed_start_ms;
static uint8_t  speed_buf[RX_BUF_SIZE];

static void speed_print_result(void)
{
    uint64_t elapsed = app_now_ms() - speed_start_ms;
    uint64_t rx_bps = 0, tx_bps = 0;

    if (elapsed == 0)
        elapsed = 1;
    rx_bps = (speed_rx_bytes * 1000ULL) / elapsed;
    tx_bps = (speed_tx_bytes * 1000ULL) / elapsed;

    uart_puts("SPEED done after "); uart_putdec((uint32_t)elapsed);
    uart_puts(" ms\n  RX "); uart_putdec((uint32_t)speed_rx_bytes);
    uart_puts(" bytes (~"); uart_putdec((uint32_t)rx_bps);
    uart_puts(" B/s)\n  TX "); uart_putdec((uint32_t)speed_tx_bytes);
    uart_puts(" bytes (~"); uart_putdec((uint32_t)tx_bps);
    uart_puts(" B/s)\n");
}

static void speed_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int n;

    if (fd == speed_listen_fd) {
        if (event & CB_EVENT_READABLE) {
            int c = wolfIP_sock_accept(s, speed_listen_fd, NULL, NULL);
            if (c >= 0) {
                /* Single-client server: if a measurement is already running,
                 * reject the newcomer rather than overwrite speed_client_fd
                 * (which would orphan the active socket - its callback is
                 * still speed_cb but the fd != speed_client_fd check would
                 * then ignore it, so it would never be closed). This keeps
                 * the invariant correct independent of MAX_TCPSOCKETS. */
                if (speed_client_fd >= 0) {
                    (void)wolfIP_sock_close(s, c);
                } else {
                    speed_client_fd = c;
                    speed_rx_bytes = 0;
                    speed_tx_bytes = 0;
                    speed_start_ms = app_now_ms();
                    wolfIP_register_callback(s, c, speed_cb, s);
                    uart_puts("SPEED client connected\n");
                }
            }
        }
        return;
    }

    if (fd != speed_client_fd)
        return;
#ifdef SPEED_DEBUG
    if (event & CB_EVENT_READABLE) uart_putc('r');
    if (event & CB_EVENT_WRITABLE) uart_putc('w');
    if (event & CB_EVENT_CLOSED)   uart_putc('C');
#endif

    /* RX: drain the whole receive buffer on each READABLE. The event is
     * edge-triggered, so reading just one chunk leaves the rest buffered;
     * once the advertised TCP window fills the peer stops sending, no new
     * READABLE fires, and the connection deadlocks (observed as a stuck
     * ~2 KB snd_wnd on the sender). The loop is bounded - recvfrom returns
     * <=0 when the buffer is empty - and reopening the buffer lets wolfIP
     * advertise a fresh window. */
    if (event & CB_EVENT_READABLE) {
        /* Bounded drain: empty up to a full window's worth of buffered data
         * (RXBUF_SIZE / MSS chunks, plus slack), then return to wolfIP_poll
         * so it can send the window-update ACK. An unbounded loop here never
         * yields to the poll, so the ACK is never sent and the transfer
         * stalls / the CPU spins. */
        int drains = 0;
        do {
            n = wolfIP_sock_recvfrom(s, fd, speed_buf, sizeof(speed_buf), 0,
                                     NULL, NULL);
            if (n > 0)
                speed_rx_bytes += (uint64_t)n;
        } while (n > 0 && ++drains < 32);
#ifdef SPEED_DEBUG
        if (drains >= 32)
            uart_putc('!');     /* hit the cap - more buffered than a window */
#endif
    }

    /* TX: bounded fill of the tx buffer each WRITABLE, then yield to poll
     * so it can flush to the wire. sock_send returns <=0 once the tx buffer
     * is full, so the loop self-limits well below the cap; the cap is just a
     * backstop against an unbounded spin. */
    if (event & CB_EVENT_WRITABLE) {
        int fills = 0;
        do {
            n = wolfIP_sock_send(s, fd, speed_buf, sizeof(speed_buf), 0);
            if (n > 0)
                speed_tx_bytes += (uint64_t)n;
        } while (n > 0 && ++fills < 32);
    }

    if (event & CB_EVENT_CLOSED) {
        speed_print_result();
        (void)wolfIP_sock_close(s, fd);
        speed_client_fd = -1;
    }
}
#endif /* SPEED_TEST */

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    int ret;

    uart_init();
    uart_puts(board_banner());

    gic_init();

    uart_puts("Initializing wolfIP stack...\n");
    wolfIP_init_static(&IPStack);

    uart_puts("Bringing up GEM (RGMII)...\n");
    ll = wolfIP_getdev(IPStack);
    ret = amd_eth_init(ll);
    if (ret < 0) {
        uart_puts("ERROR: amd_eth_init failed: ");
        uart_puthex((uint32_t)ret);
        uart_puts("\n");
        while (1)
            ;
    }
    uart_puts("  link "); uart_puts((ret & 0x100) ? "UP" : "DOWN");
    uart_puts(", PHY=");      uart_puthex((uint32_t)(ret & 0xFF));
    uart_puts("\n");

    /* Unmask CPU IRQs on boards that use IRQ-driven RX (no-op on the
     * poll-only boards, where the GEM interrupt is left masked). */
    board_irq_setup();

#ifdef DEBUG_GEM
    uart_puts("Initial GEM state:\n");
    gem_dump_state();
#endif

#ifdef DHCP
    if (dhcp_client_init(IPStack) >= 0) {
        uint64_t dhcp_start = app_now_ms();
        const uint64_t dhcp_timeout = 15000;
#ifdef DEBUG_GEM
        uint64_t dbg_next = dhcp_start + 1000;
#endif
        uart_puts("Starting DHCP client...\n");
        while (!dhcp_bound(IPStack) && dhcp_client_is_running(IPStack)
               && (app_now_ms() - dhcp_start) < dhcp_timeout) {
            (void)wolfIP_poll(IPStack, app_now_ms());
#ifdef DEBUG_GEM
            if (app_now_ms() >= dbg_next) {
                dbg_next += 1000;
                uart_puts("  ["); uart_putdec((uint32_t)(app_now_ms() - dhcp_start));
                uart_puts(" ms] bound=");
                uart_putdec(dhcp_bound(IPStack) ? 1u : 0u);
                uart_puts(" running=");
                uart_putdec(dhcp_client_is_running(IPStack) ? 1u : 0u);
                uart_puts("\n");
                gem_dump_state();
            }
#endif
        }
        if (dhcp_bound(IPStack)) {
            ip4 ip = 0, nm = 0, gw = 0;
            wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
            uart_puts("DHCP bound:\n  IP: ");   uart_putip4(ip);
            uart_puts("\n  Mask: "); uart_putip4(nm);
            uart_puts("\n  GW:   "); uart_putip4(gw);
            uart_puts("\n");
        } else {
            ip4 ip = atoip4(WOLFIP_IP);
            ip4 nm = atoip4(WOLFIP_NETMASK);
            ip4 gw = atoip4(WOLFIP_GW);
            uart_puts("DHCP timeout - using static IP\n");
            wolfIP_ipconfig_set(IPStack, ip, nm, gw);
        }
    }
#else
    {
        ip4 ip = atoip4(WOLFIP_IP);
        ip4 nm = atoip4(WOLFIP_NETMASK);
        ip4 gw = atoip4(WOLFIP_GW);
        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
        uart_puts("Static IP: "); uart_putip4(ip); uart_puts("\n");
    }
#endif

#ifdef SPEED_TEST
    uart_puts("Opening TCP throughput server on port ");
    uart_putdec(SPEED_PORT); uart_puts("\n");
    speed_listen_fd = wolfIP_sock_socket(IPStack, AF_INET,
                                         IPSTACK_SOCK_STREAM, 0);
    if (speed_listen_fd < 0) {
        uart_puts("ERROR: TCP socket alloc failed: ");
        uart_puthex((uint32_t)speed_listen_fd); uart_puts("\n");
        while (1)
            ;
    }
    wolfIP_register_callback(IPStack, speed_listen_fd, speed_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(SPEED_PORT);
    addr.sin_addr.s_addr = 0;
    if (wolfIP_sock_bind(IPStack, speed_listen_fd,
                         (struct wolfIP_sockaddr *)&addr, sizeof(addr)) < 0) {
        uart_puts("ERROR: TCP bind failed\n");
        while (1)
            ;
    }
    if (wolfIP_sock_listen(IPStack, speed_listen_fd, 1) < 0) {
        uart_puts("ERROR: TCP listen failed\n");
        while (1)
            ;
    }

    uart_puts("Ready. RX: dd if=/dev/zero bs=1460 count=N | nc <ip> ");
    uart_putdec(SPEED_PORT);
    uart_puts("\n       TX: nc <ip> "); uart_putdec(SPEED_PORT);
    uart_puts(" </dev/null | pv -r >/dev/null\n\n");
#else
    uart_puts("Opening UDP echo socket on port ");
    uart_putdec(ECHO_PORT); uart_puts("\n");
    udp_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        uart_puts("ERROR: UDP socket alloc failed: ");
        uart_puthex((uint32_t)udp_fd); uart_puts("\n");
        while (1)
            ;
    }
    wolfIP_register_callback(IPStack, udp_fd, udp_echo_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    if (wolfIP_sock_bind(IPStack, udp_fd,
                         (struct wolfIP_sockaddr *)&addr, sizeof(addr)) < 0) {
        uart_puts("ERROR: UDP bind failed on port ");
        uart_putdec(ECHO_PORT); uart_puts("\n");
        while (1)
            ;
    }

    uart_puts("Ready. Try: nc -u <leased-ip> 7\n\n");
#endif /* SPEED_TEST */

    /* Busy-poll with a real-millisecond clock. The previous tick++ +
     * delay_ms(1) throttled the stack to ~1 poll/ms (a hard throughput
     * ceiling) and fed wolfIP a counter that only approximated real ms. */
#ifdef SPEED_DEBUG
    {
        uint64_t last_hb = app_now_ms();
        for (;;) {
            uint64_t now = app_now_ms();
            (void)wolfIP_poll(IPStack, now);
            if (now - last_hb >= 1000) {
                last_hb = now;
                uart_putc('P');
            }
        }
    }
#else
    for (;;) {
        (void)wolfIP_poll(IPStack, app_now_ms());
    }
#endif

    return 0;
}
