/* phy_dp83867.c
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
 * TI DP83867IR PHY init (RGMII to the PS GEM).
 *
 * The DP83867 needs explicit RGMII TX and RX clock delay configuration
 * (CFG4 / RGMIICTL extended registers) because these boards route
 * RGMII signals as a straight-through trace without external delay.
 * Without this the link comes up at 1 Gbps but carries corrupt data
 * (random RX frames, no TX). The Linux dp83867 driver and Xilinx
 * device tree both apply a 2.0 ns TX + 2.0 ns RX skew - we match.
 *
 * Extended registers (>0x1F) are accessed via the IEEE-defined indirect
 * pair (REGCR=0x0D, ADDAR=0x0E):
 *   1. Write REGCR = 0x001F (address-of, devad 31).
 *   2. Write ADDAR = <extended register address>.
 *   3. Write REGCR = 0x401F (data, devad 31, no-increment).
 *   4. Read/Write ADDAR = <data>.
 */
#include <stdint.h>
#include "gem.h"
#include "phy_dp83867.h"
#include "timer.h"
#include "uart.h"

/* Standard IEEE PHY registers (clause 22) */
#define PHY_BMCR            0x00
#define PHY_BMSR            0x01
#define PHY_ID1             0x02
#define PHY_ID2             0x03
#define PHY_ANAR            0x04
#define PHY_GBCR            0x09
#define PHY_GBSR            0x0A
#define PHY_REGCR           0x0D
#define PHY_ADDAR           0x0E

#define BMCR_RESET          (1u << 15)
#define BMCR_ANRESTART      (1u << 9)
#define BMCR_ANEN           (1u << 12)

#define BMSR_ANCOMPLETE     (1u << 5)
#define BMSR_LINK_UP        (1u << 2)

/* DP83867 extended registers (accessed via REGCR/ADDAR, devad 0x1F) */
#define DP83867_CFG4        0x0031   /* Configuration 4 (RX_CTRL strap fix) */
#define DP83867_RGMIICTL    0x0032   /* RGMII control */
#define DP83867_STRAP_STS1  0x006E   /* Strap status register (read-only) */
#define DP83867_RGMIIDCTL   0x0086   /* RGMII delay control */
#define DP83867_IO_MUX_CFG  0x0170   /* IO MUX config (impedance) */

/* Clause-22 register (direct access) */
#define DP83867_PHYCR       0x10     /* PHY Control register */
#define PHYCR_FIFO_DEPTH_MASK (3u << 14)
#define PHYCR_FIFO_DEPTH_8B   (3u << 14)

/* RGMIICTL bits */
#define RGMIICTL_RX_DELAY_EN (1u << 0)
#define RGMIICTL_TX_DELAY_EN (1u << 1)

/* RGMIIDCTL: TX delay in [3:0], RX delay in [7:4], each step ~0.25 ns.
 * 0x8 -> 2.0 ns (matches the Linux/Xilinx default). */
#define RGMIIDCTL_DELAY_2NS  (0x8u | (0x8u << 4))

/* Speed read from PHY status register (DP83867 0x11) */
#define DP83867_PHYSTS       0x0011
#define PHYSTS_SPEED_MASK    (3u << 14)
#define PHYSTS_SPEED_1000    (2u << 14)
#define PHYSTS_SPEED_100     (1u << 14)
#define PHYSTS_SPEED_10      (0u << 14)
#define PHYSTS_DUPLEX        (1u << 13)

static int phy_ext_write(uint8_t phy_addr, uint16_t ext_reg, uint16_t val)
{
    int rc;
    rc = gem_mdio_write(phy_addr, PHY_REGCR, 0x001Fu);
    if (rc < 0) return rc;
    rc = gem_mdio_write(phy_addr, PHY_ADDAR, ext_reg);
    if (rc < 0) return rc;
    rc = gem_mdio_write(phy_addr, PHY_REGCR, 0x401Fu);
    if (rc < 0) return rc;
    return gem_mdio_write(phy_addr, PHY_ADDAR, val);
}

static int phy_ext_read(uint8_t phy_addr, uint16_t ext_reg, uint16_t *out)
{
    int rc;
    rc = gem_mdio_write(phy_addr, PHY_REGCR, 0x001Fu);
    if (rc < 0) return rc;
    rc = gem_mdio_write(phy_addr, PHY_ADDAR, ext_reg);
    if (rc < 0) return rc;
    rc = gem_mdio_write(phy_addr, PHY_REGCR, 0x401Fu);
    if (rc < 0) return rc;
    return gem_mdio_read(phy_addr, PHY_ADDAR, out);
}

int dp83867_init(uint8_t phy_addr, int *speed_out, int *full_duplex_out)
{
    uint16_t id1 = 0;
    uint16_t id2 = 0;
    uint16_t bmcr;
    uint16_t bmsr;
    uint16_t physts;
    int i;

    if (gem_mdio_read(phy_addr, PHY_ID1, &id1) < 0)
        return -1;
    if (gem_mdio_read(phy_addr, PHY_ID2, &id2) < 0)
        return -2;
    uart_puts("DP83867: ID1="); uart_puthex(id1);
    uart_puts(" ID2=");        uart_puthex(id2);
    uart_puts("\n");
    /* DP83867 OUI = 0x2000A23x. ID1=0x2000, ID2 upper bits match. */
    if (id1 != 0x2000u || (id2 & 0xFFF0u) != 0xA230u) {
        uart_puts("  warn: PHY ID does not match DP83867, continuing\n");
    }

    /* Soft reset. */
    if (gem_mdio_write(phy_addr, PHY_BMCR, BMCR_RESET) < 0)
        return -3;
    for (i = 0; i < 1000; i++) {
        delay_ms(1);
        if (gem_mdio_read(phy_addr, PHY_BMCR, &bmcr) < 0)
            return -4;
        if ((bmcr & BMCR_RESET) == 0)
            break;
    }
    if (i == 1000)
        return -5;

    /* Order below mirrors the Linux/U-Boot dp83867_config sequence:
     *   1. Strap fix (CFG4 bit 7) right after SW reset.
     *   2. PHYCR FIFO depth RMW.
     *   3. RGMIICTL RMW to enable both delays.
     *   4. RGMIIDCTL set delay values.
     *   5. Restart AN (caller does after we return).
     */
    {
        uint16_t strap = 0;
        uint16_t cfg4_before = 0;
        uint16_t cfg4_after = 0;
        uint16_t iomux = 0;
        uint16_t rgmiictl = 0;
        uint16_t phycr_before = 0;
        uint16_t phycr_after = 0;

        (void)phy_ext_read(phy_addr, DP83867_STRAP_STS1, &strap);
        (void)phy_ext_read(phy_addr, DP83867_IO_MUX_CFG, &iomux);
        (void)phy_ext_read(phy_addr, DP83867_CFG4, &cfg4_before);

        /* 1. RX_CTRL strap quirk. */
        cfg4_after = cfg4_before & ~(1u << 7);
        if (phy_ext_write(phy_addr, DP83867_CFG4, cfg4_after) < 0)
            return -6;

        /* 2. PHYCR FIFO depth = 8 bytes (RMW so we keep Auto-MDIX,
         * power-down detect, etc., that the strap brought up). */
        (void)gem_mdio_read(phy_addr, DP83867_PHYCR, &phycr_before);
        phycr_after = (phycr_before & ~PHYCR_FIFO_DEPTH_MASK)
                    | PHYCR_FIFO_DEPTH_8B;
        if (gem_mdio_write(phy_addr, DP83867_PHYCR, phycr_after) < 0)
            return -7;

        /* 3. RGMIICTL: enable TX and RX clock delays (RMW). */
        (void)phy_ext_read(phy_addr, DP83867_RGMIICTL, &rgmiictl);
        rgmiictl |= RGMIICTL_RX_DELAY_EN | RGMIICTL_TX_DELAY_EN;
        if (phy_ext_write(phy_addr, DP83867_RGMIICTL, rgmiictl) < 0)
            return -8;

        /* 4. RGMIIDCTL: 2.0 ns each (matches Linux ti,*-internal-delay=8). */
        if (phy_ext_write(phy_addr, DP83867_RGMIIDCTL,
                          RGMIIDCTL_DELAY_2NS) < 0)
            return -9;

#ifdef DEBUG_PHY
        /* Verbose pre-AN dump so we can diff against U-Boot's state. */
        uart_puts("DP83867 pre-AN: STRAP_STS1=");  uart_puthex(strap);
        uart_puts(" IO_MUX_CFG=");                 uart_puthex(iomux);
        uart_puts("\n             CFG4: ");        uart_puthex(cfg4_before);
        uart_puts(" -> ");                         uart_puthex(cfg4_after);
        uart_puts("  PHYCR: ");                    uart_puthex(phycr_before);
        uart_puts(" -> ");                         uart_puthex(phycr_after);
        uart_puts("\n             RGMIICTL=");     uart_puthex(rgmiictl);
        uart_puts(" RGMIIDCTL=");                  uart_puthex(RGMIIDCTL_DELAY_2NS);
        uart_puts("\n");

        {
            uint16_t v;
            (void)phy_ext_read(phy_addr, DP83867_CFG4, &v);
            uart_puts("DP83867 readback: CFG4=");   uart_puthex(v);
            (void)phy_ext_read(phy_addr, DP83867_RGMIICTL, &v);
            uart_puts(" RGMIICTL=");                uart_puthex(v);
            (void)phy_ext_read(phy_addr, DP83867_RGMIIDCTL, &v);
            uart_puts(" RGMIIDCTL=");               uart_puthex(v);
            (void)gem_mdio_read(phy_addr, DP83867_PHYCR, &v);
            uart_puts(" PHYCR=");                   uart_puthex(v);
            uart_puts("\n");
        }
#else
        (void)strap; (void)iomux;
        (void)cfg4_before; (void)cfg4_after;
        (void)phycr_before; (void)phycr_after;
        (void)rgmiictl;
#endif
    }

    /* Advertise 10/100/1000 full + half duplex. */
    if (gem_mdio_write(phy_addr, PHY_ANAR, 0x01E1u) < 0)
        return -13;
    if (gem_mdio_write(phy_addr, PHY_GBCR, (1u << 9) | (1u << 8)) < 0)
        return -14;

    /* Restart AN. */
    if (gem_mdio_write(phy_addr, PHY_BMCR, BMCR_ANEN | BMCR_ANRESTART) < 0)
        return -10;

    /* Wait up to 5 s for AN complete, polling at 50 ms. AN typically
     * needs 100-1500 ms depending on link partner. Report progress so
     * a hung negotiation is visible on UART. */
    uart_puts("DP83867: waiting for autoneg");
    for (i = 0; i < 100; i++) {
        delay_ms(50);
        if (gem_mdio_read(phy_addr, PHY_BMSR, &bmsr) < 0)
            return -11;
        if (bmsr & BMSR_ANCOMPLETE) {
            uart_puts(" done (");
            uart_putdec((uint32_t)i * 50u);
            uart_puts("ms)\n");
            break;
        }
        if ((i % 10) == 9)
            uart_putc('.');
    }
    if (!(bmsr & BMSR_ANCOMPLETE))
        uart_puts(" TIMEOUT\n");

    /* Give the PHY a moment to latch the negotiated speed before we
     * read PHYSTS - on DP83867 link-OK and PHYSTS update slightly
     * after AN_COMPLETE asserts. */
    delay_ms(100);

    /* After AN_COMPLETE, the 1000BASE-T link still needs to finish
     * master/slave training and have BOTH receivers report OK before
     * BMSR.LINK_UP asserts. This can take several hundred ms more.
     * Poll BMSR (double-read for latch) up to 5 s, dumping GBSR each
     * iteration so we can see remote_rx_status flip. */
    {
        int j;
        uint16_t gbsr = 0;
        uint16_t bmsr2 = 0;
        uart_puts("DP83867: waiting for link");
        for (j = 0; j < 100; j++) {
            delay_ms(50);
            (void)gem_mdio_read(phy_addr, PHY_BMSR, &bmsr2);
            (void)gem_mdio_read(phy_addr, PHY_BMSR, &bmsr2);
            (void)gem_mdio_read(phy_addr, PHY_GBSR, &gbsr);
            if (bmsr2 & BMSR_LINK_UP) {
                uart_puts(" UP (");
                uart_putdec((uint32_t)j * 50u);
                uart_puts("ms) GBSR=");
                uart_puthex(gbsr);
                uart_puts("\n");
                bmsr = bmsr2;
                break;
            }
            if ((j % 10) == 9) {
                uart_puts(" [");
                uart_putdec((uint32_t)(j + 1) * 50u);
                uart_puts("ms GBSR=");
                uart_puthex(gbsr);
                uart_puts("]");
            }
        }
        if (!(bmsr2 & BMSR_LINK_UP))
            uart_puts(" TIMEOUT\n");
    }

    if (gem_mdio_read(phy_addr, DP83867_PHYSTS, &physts) < 0)
        return -12;

#ifdef DEBUG_PHY
    {
        uint16_t bmcr_now = 0;
        uint16_t lpa = 0;
        uint16_t gbsr = 0;
        (void)gem_mdio_read(phy_addr, PHY_BMCR, &bmcr_now);
        (void)gem_mdio_read(phy_addr, 0x05, &lpa);     /* MII LPA */
        (void)gem_mdio_read(phy_addr, PHY_GBSR, &gbsr);
        uart_puts("DP83867 regs: BMCR=");   uart_puthex(bmcr_now);
        uart_puts(" BMSR=");                uart_puthex(bmsr);
        uart_puts(" LPA=");                 uart_puthex(lpa);
        uart_puts(" GBSR=");                uart_puthex(gbsr);
        uart_puts(" PHYSTS=");              uart_puthex(physts);
        uart_puts("\n");
    }
#endif

    if ((physts & PHYSTS_SPEED_MASK) == PHYSTS_SPEED_1000)
        *speed_out = 1000;
    else if ((physts & PHYSTS_SPEED_MASK) == PHYSTS_SPEED_100)
        *speed_out = 100;
    else
        *speed_out = 10;
    *full_duplex_out = (physts & PHYSTS_DUPLEX) ? 1 : 0;

    uart_puts("DP83867 link: ");
    uart_putdec((uint32_t)*speed_out);
    uart_puts(*full_duplex_out ? " Mbps FD\n" : " Mbps HD\n");

    return 0;   /* init OK; link state is read via dp83867_link_status() */
}

int dp83867_link_status(uint8_t phy_addr)
{
    uint16_t bmsr;
    /* BMSR latches link down; read twice. */
    if (gem_mdio_read(phy_addr, PHY_BMSR, &bmsr) < 0)
        return -1;
    if (gem_mdio_read(phy_addr, PHY_BMSR, &bmsr) < 0)
        return -1;
    return (bmsr & BMSR_LINK_UP) ? 1 : 0;
}
