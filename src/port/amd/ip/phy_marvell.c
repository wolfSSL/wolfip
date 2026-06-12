/* phy_marvell.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Marvell 88E1518 (Alaska) RGMII PHY driver for the Xilinx ZC702
 * on-board PS-GEM RJ45. The DP83867 driver cannot be reused here: the
 * 88E1518 uses Marvell's paged register model and a different RGMII
 * internal-delay control, and the DP83867 MMD writes (registers 13/14)
 * land on Marvell MMD space and prevent auto-negotiation from
 * completing. This driver does a clean reset, programs the RGMII RX/TX
 * internal delays, then runs standard clause-22 auto-negotiation.
 */
#include <stdint.h>
#include "gem.h"
#include "uart.h"
#include "timer.h"
#include "phy_marvell.h"

/* Standard clause-22 MII registers (page 0). */
#define MII_BMCR            0x00u
#define MII_BMSR            0x01u
#define MII_ID1             0x02u
#define MII_ID2             0x03u
#define MII_ANAR            0x04u
#define MII_GBCR            0x09u   /* 1000BASE-T control */

#define BMCR_RESET          (1u << 15)
#define BMCR_ANEN           (1u << 12)
#define BMCR_ANRESTART      (1u << 9)

#define BMSR_ANCOMPLETE     (1u << 5)
#define BMSR_LINK_UP        (1u << 2)

/* Marvell paging: register 22 selects the page for registers 0..21. */
#define MARVELL_PAGE_SEL    22u

/* Page 2, register 21: MAC Specific Control Register 2. RGMII internal
 * delay enables live here. */
#define MARVELL_PAGE_MAC    2u
#define M88E1518_MAC_CTRL2  21u
#define MAC_CTRL2_RX_DELAY  (1u << 5)   /* add internal delay to RGMII RXCLK */
#define MAC_CTRL2_TX_DELAY  (1u << 4)   /* add internal delay to RGMII TXCLK */

/* Page 0, register 17: Copper Specific Status Register 1. */
#define M88E1518_COPPER_STS 17u
#define COPPER_STS_SPEED_MASK   (3u << 14)
#define COPPER_STS_SPEED_1000   (2u << 14)
#define COPPER_STS_SPEED_100    (1u << 14)
#define COPPER_STS_FULL_DUPLEX  (1u << 13)
#define COPPER_STS_RESOLVED     (1u << 11)

static int marvell_set_page(uint8_t phy_addr, uint16_t page)
{
    return gem_mdio_write(phy_addr, MARVELL_PAGE_SEL, page);
}

int marvell_88e1518_init(uint8_t phy_addr, int *speed_out, int *full_duplex_out)
{
    uint16_t reg;
    uint16_t bmsr = 0;
    int i;
    int speed = 10;
    int fd = 0;

    /* Program the RGMII RX/TX internal delays (page 2, register 21). The
     * 88E1518 latches these on the next software reset, so set them
     * before the reset below. */
    if (marvell_set_page(phy_addr, MARVELL_PAGE_MAC) < 0)
        return -1;
    /* From here the PHY is on page 2; restore page 0 on every error exit so
     * later generic clause-22 accesses (BMSR/BMCR on page 0) are not left
     * pointing at the MAC page. */
    if (gem_mdio_read(phy_addr, M88E1518_MAC_CTRL2, &reg) < 0) {
        (void)marvell_set_page(phy_addr, 0);
        return -2;
    }
    reg |= (MAC_CTRL2_RX_DELAY | MAC_CTRL2_TX_DELAY);
    if (gem_mdio_write(phy_addr, M88E1518_MAC_CTRL2, reg) < 0) {
        (void)marvell_set_page(phy_addr, 0);
        return -3;
    }
    if (marvell_set_page(phy_addr, 0) < 0)
        return -4;

    /* Software reset to apply the delay configuration. */
    if (gem_mdio_write(phy_addr, MII_BMCR, BMCR_RESET) < 0)
        return -5;
    for (i = 0; i < 100; i++) {
        delay_ms(5);
        if (gem_mdio_read(phy_addr, MII_BMCR, &reg) < 0)
            return -6;
        if (!(reg & BMCR_RESET))
            break;
    }
    if (reg & BMCR_RESET)
        return -7;

    /* Advertise 10/100 (full+half) and 1000 (full+half), then restart
     * auto-negotiation. */
    if (gem_mdio_write(phy_addr, MII_ANAR, 0x01E1u) < 0)
        return -8;
    if (gem_mdio_write(phy_addr, MII_GBCR, (1u << 9) | (1u << 8)) < 0)
        return -9;
    if (gem_mdio_write(phy_addr, MII_BMCR, BMCR_ANEN | BMCR_ANRESTART) < 0)
        return -10;

    /* Wait up to 5 s for AN to complete, 50 ms poll. */
    uart_puts("88E1518: waiting for autoneg");
    for (i = 0; i < 100; i++) {
        delay_ms(50);
        if (gem_mdio_read(phy_addr, MII_BMSR, &bmsr) < 0)
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

    /* Wait up to 5 s for the copper link to come up (BMSR is latch-low,
     * so double-read). */
    uart_puts("88E1518: waiting for link");
    for (i = 0; i < 100; i++) {
        delay_ms(50);
        (void)gem_mdio_read(phy_addr, MII_BMSR, &bmsr);
        (void)gem_mdio_read(phy_addr, MII_BMSR, &bmsr);
        if (bmsr & BMSR_LINK_UP) {
            uart_puts(" UP (");
            uart_putdec((uint32_t)i * 50u);
            uart_puts("ms)\n");
            break;
        }
        if ((i % 10) == 9)
            uart_putc('.');
    }
    if (!(bmsr & BMSR_LINK_UP))
        uart_puts(" TIMEOUT\n");

    /* Read the resolved speed/duplex from the Copper Specific Status
     * register (page 0, register 17). */
    if (gem_mdio_read(phy_addr, M88E1518_COPPER_STS, &reg) < 0)
        return -12;
#ifdef DEBUG_PHY
    uart_puts("88E1518 copper status="); uart_puthex(reg); uart_puts("\n");
#endif
    if (reg & COPPER_STS_RESOLVED) {
        if ((reg & COPPER_STS_SPEED_MASK) == COPPER_STS_SPEED_1000)
            speed = 1000;
        else if ((reg & COPPER_STS_SPEED_MASK) == COPPER_STS_SPEED_100)
            speed = 100;
        else
            speed = 10;
        fd = (reg & COPPER_STS_FULL_DUPLEX) ? 1 : 0;
    }

    if (speed_out)
        *speed_out = speed;
    if (full_duplex_out)
        *full_duplex_out = fd;
    return 0;
}
