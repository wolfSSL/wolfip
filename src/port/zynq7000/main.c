/* main.c
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
 * wolfIP UDP echo + DHCP client demo for Xilinx Zynq-7000 (Cortex-A9,
 * ARMv7-A 32-bit, GEM0 -> on-board RJ45).
 *
 * UNTESTED ON HARDWARE -- structural scaffold mirroring src/port/zcu102/.
 */
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "../../../wolfip.h"
#include "board.h"
#include "uart.h"
#include "gic.h"
#include "gem.h"
#include "timer.h"

#define ECHO_PORT       7
#define RX_BUF_SIZE     1500

static struct wolfIP *IPStack;
static int udp_fd = -1;
static uint8_t udp_rx_buf[RX_BUF_SIZE];

/* Override newlib memset/memcpy with plain bytewise versions via
 * linker --wrap. The same defensive pattern we used on the AArch64
 * port; whether the ARMv7 newlib variant has an equivalent issue
 * has not been verified, so we keep the override pending lab
 * validation. The Makefile passes -Wl,--wrap=memset -Wl,--wrap=memcpy
 * so all calls get redirected to these __wrap_ functions. */
void *__wrap_memset(void *s, int c, unsigned long n)
{
    unsigned char *p = (unsigned char *)s;
    while (n--)
        *p++ = (unsigned char)c;
    return s;
}

void *__wrap_memcpy(void *dest, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dest;
}

/* ARMv7 exception handlers in startup.S simply hang on faults
 * (undef, prefetch abort, data abort). No C-side reporter required
 * for this scaffold; bring-up will add CP15 fault-status reads
 * (DFSR / IFSR / DFAR / IFAR) when the lab board is available. */

/* wolfIP needs a 32-bit random word for protocol identifiers (TCP ISN,
 * DHCP xid, DNS id, ephemeral source port, IP fragment id). We delegate
 * to the port-local memuse-pattern entropy source (entropy.c), which
 * follows the algorithm of wolfCrypt's wc_Entropy_Get() but is
 * self-contained for cert isolation. */
extern uint32_t zynq7000_get_random32(void);

uint32_t wolfIP_getrandom(void)
{
    return zynq7000_get_random32();
}

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
        uart_puts(" bytes from "); uart_putip4(peer.sin_addr.s_addr);
        uart_puts("\n");
    }
}

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint64_t tick = 0;
    int ret;

    uart_init();
    uart_puts("\n\n=== wolfIP Zynq-7000 (Cortex-A9 SVC) ===\n");
    uart_puts("MMU on, caches on. Bringing up GIC-390...\n");

    gic_init();

    uart_puts("Initializing wolfIP stack...\n");
    wolfIP_init_static(&IPStack);

    uart_puts("Bringing up GEM0 (RGMII, DP83867)...\n");
    ll = wolfIP_getdev(IPStack);
    ret = zcu102_eth_init(ll);
    if (ret < 0) {
        uart_puts("ERROR: zcu102_eth_init failed: ");
        uart_puthex((uint32_t)ret);
        uart_puts("\n");
        while (1)
            ;
    }
    uart_puts("  link "); uart_puts((ret & 0x100) ? "UP" : "DOWN");
    uart_puts(", PHY=");      uart_puthex((uint32_t)(ret & 0xFF));
    uart_puts("\n");

    /* Unmask IRQ + FIQ at CPU now that GEM0 SPI is enabled at GICD. */
    irq_enable();
#if 0   /* DEBUG_GIC self-test block uses AArch64 system regs;
         * disabled on ARMv7 until the ARMv7-equivalent diagnostics
         * (DAIF -> CPSR.I/F, ISR_EL1 -> CP15 c12 c1 0, etc.) are
         * filled in during bring-up. */
    uart_puts("IRQ enabled. Self-test: firing SGI 0...\n");
    {
        uint32_t before = gic_total_irqs();
        uint64_t daif, scr, vbar;
        __asm__ volatile ("mrs %0, daif" : "=r"(daif));
        __asm__ volatile ("mrs %0, scr_el3" : "=r"(scr));
        __asm__ volatile ("mrs %0, vbar_el3" : "=r"(vbar));
        uart_puts("  pre: DAIF="); uart_puthex((uint32_t)daif);
        uart_puts(" SCR_EL3="); uart_puthex((uint32_t)scr);
        uart_puts(" VBAR_EL3="); uart_puthex((uint32_t)vbar);
        uart_puts("\n");
        {
            uint32_t vec_irq_curr_spx;
            vec_irq_curr_spx = *(volatile uint32_t *)(vbar + 0x280);
            uart_puts("  vec[Cur SPx IRQ] @ ");
            uart_puthex((uint32_t)(vbar + 0x280));
            uart_puts(" = ");
            uart_puthex(vec_irq_curr_spx);
            uart_puts(" (B opcode: top byte 0x14 expected)\n");
        }
        uart_puts("  GICD_CTLR="); uart_puthex(*(volatile uint32_t *)(GICD_BASE + 0x000));
        uart_puts(" GICD_ISENABLER(0)="); uart_puthex(*(volatile uint32_t *)(GICD_BASE + 0x100));
        uart_puts(" GICD_IGROUPR(0)="); uart_puthex(*(volatile uint32_t *)(GICD_BASE + 0x080));
        uart_puts("\n");
        uart_puts("  GICC_CTLR="); uart_puthex(*(volatile uint32_t *)(GICC_BASE + 0x000));
        uart_puts(" GICC_PMR="); uart_puthex(*(volatile uint32_t *)(GICC_BASE + 0x004));
        uart_puts("\n");
        gic_self_test_sgi(0);
        delay_ms(10);
        {
            uint64_t isr, rpr;
            __asm__ volatile ("mrs %0, isr_el1" : "=r"(isr));
            rpr = *(volatile uint32_t *)(GICC_BASE + 0x014);
            uart_puts("  post-SGI: ISR_EL1=");
            uart_puthex((uint32_t)isr);
            uart_puts(" (bit7=I, bit6=F, bit8=A)\n");
            uart_puts("  GICC_RPR="); uart_puthex((uint32_t)rpr);
            uart_puts(" (running priority; 0xFF=idle)\n");
        }
        uart_puts("  SGI fired. gic_total_irqs: ");
        uart_putdec(before);
        uart_puts(" -> ");
        uart_putdec(gic_total_irqs());
        uart_puts(" last_intid=");
        uart_puthex(gic_last_intid());
        uart_puts("\n  GICD_ISPENDR(0)="); uart_puthex(*(volatile uint32_t *)(GICD_BASE + 0x200));
        uart_puts(" GICC_HPPIR="); uart_puthex(*(volatile uint32_t *)(GICC_BASE + 0x018));
        uart_puts("\n");
        {
            uint32_t iar = *(volatile uint32_t *)(GICC_BASE + 0x00C);
            uart_puts("  polled GICC_IAR="); uart_puthex(iar);
            uart_puts("\n");
            if ((iar & 0x3FF) != 0x3FF) {
                *(volatile uint32_t *)(GICC_BASE + 0x010) = iar;
                uart_puts("  EOI'd. polled GICC_HPPIR after=");
                uart_puthex(*(volatile uint32_t *)(GICC_BASE + 0x018));
                uart_puts("\n");
            }
        }
        /* Extra system-register snapshot. FSBL/ATF sometimes leaves
         * HCR_EL2 / MDCR_EL3 / OSLAR_EL1 with bits set that affect
         * exception routing or debug halt; dump them so we can rule
         * those out. NOTE: WFI wake test was tried here and hangs
         * the CPU even though ISR_EL1.I=1 was observed earlier - the
         * GIC appears to assert and deassert nIRQ within a few cycles
         * rather than holding it level until ACK. That is consistent
         * with edge-triggered SGI behavior but is not what the spec
         * requires; it leaves no time for the exception logic to
         * latch the event. */
        {
            uint64_t hcr, mdcr, sctlr, oslsr;
            __asm__ volatile ("mrs %0, hcr_el2"   : "=r"(hcr));
            __asm__ volatile ("mrs %0, mdcr_el3"  : "=r"(mdcr));
            __asm__ volatile ("mrs %0, sctlr_el3" : "=r"(sctlr));
            __asm__ volatile ("mrs %0, oslsr_el1" : "=r"(oslsr));
            uart_puts("  HCR_EL2=");   uart_puthex((uint32_t)hcr);
            uart_puts(" MDCR_EL3=");   uart_puthex((uint32_t)mdcr);
            uart_puts("\n  SCTLR_EL3="); uart_puthex((uint32_t)sctlr);
            uart_puts(" OSLSR_EL1="); uart_puthex((uint32_t)oslsr);
            uart_puts("\n");
        }
    }
#endif
#ifdef DEBUG_GEM
    uart_puts("Initial GEM state:\n");
    gem_dump_state();
#endif

#ifdef DHCP
    if (dhcp_client_init(IPStack) >= 0) {
        uint32_t dhcp_elapsed = 0;
        const uint32_t dhcp_timeout = 15000;
        uart_puts("Starting DHCP client...\n");
        while (!dhcp_bound(IPStack) && dhcp_client_is_running(IPStack)
               && dhcp_elapsed < dhcp_timeout) {
            (void)wolfIP_poll(IPStack, tick);
            tick++;
            delay_ms(1);
            dhcp_elapsed++;
            /* gic_poll_dispatch removed - eth_poll already polls
             * GEM_ISR directly. Doubling up here just spins. */
#ifdef DEBUG_GEM
            if ((dhcp_elapsed % 1000) == 0) {
                uart_puts("  ["); uart_putdec(dhcp_elapsed);
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

    uart_puts("Opening UDP echo socket on port ");
    uart_putdec(ECHO_PORT); uart_puts("\n");
    udp_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    wolfIP_register_callback(IPStack, udp_fd, udp_echo_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    (void)wolfIP_sock_bind(IPStack, udp_fd,
                           (struct wolfIP_sockaddr *)&addr, sizeof(addr));

    uart_puts("Ready. Try: nc -u <leased-ip> 7\n\n");

    for (;;) {
        (void)wolfIP_poll(IPStack, tick++);
        delay_ms(1);
    }

    return 0;
}
