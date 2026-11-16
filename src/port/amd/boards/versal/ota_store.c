/* ota_store.c
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
 *
 * QSPI slot handling for the Versal wolfBoot + wolfIP update demo. wolfBoot
 * (dual-boot, no swap) boots whichever of its two slots holds the higher
 * valid version and reports the choice in /chosen/wolfboot,boot-part of the
 * device tree it passes in x0. Images stay encrypted in flash, so this code
 * treats them as opaque and only handles the plaintext slot trailers.
 */
#include <stdint.h>
#include <string.h>

#include "uart.h"
#include "ota.h"
#include "ota_store.h"

#include "wolfboot/wolfboot.h"
#include "image.h"
#include "hal.h"

#ifndef OTA_APP_VERSION
#define OTA_APP_VERSION 1
#endif
/* Demo knob: never confirm, and reset after this long, to show rollback. */
#ifndef OTA_NEVER_CONFIRM_MS
#define OTA_NEVER_CONFIRM_MS 15000U
#endif

#define OTA_FDT_MAGIC       0xD00DFEEDU
#define OTA_FDT_BEGIN_NODE  1U
#define OTA_FDT_END_NODE    2U
#define OTA_FDT_PROP        3U
#define OTA_FDT_NOP         4U
#define OTA_FDT_END         9U
#define OTA_FDT_MAX_SIZE    0x100000U

/* x0 at entry, saved by startup_aarch64.S. */
extern uint64_t boot_arg0;

static int store_ready;
static int store_part = -1;
static uint32_t store_t0;
static int store_probation;

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Find a 4-byte property by name anywhere in the tree. */
static int fdt_find_u32(const uint8_t *fdt, const char *name, uint32_t *val)
{
    uint32_t total, off_struct, off_str, size_struct, pos, tok, len, nameoff;
    const char *pname;

    if (fdt == NULL || be32(fdt) != OTA_FDT_MAGIC)
        return -1;
    total = be32(fdt + 4);
    off_struct = be32(fdt + 8);
    off_str = be32(fdt + 12);
    size_struct = be32(fdt + 36);
    if (total > OTA_FDT_MAX_SIZE || off_struct >= total || off_str >= total ||
            size_struct > total - off_struct)
        return -1;
    pos = 0;
    while (pos + 4 <= size_struct) {
        tok = be32(fdt + off_struct + pos);
        pos += 4;
        if (tok == OTA_FDT_BEGIN_NODE) {
            while (pos < size_struct && fdt[off_struct + pos] != 0)
                pos++;
            pos = (pos + 4) & ~3U;
        }
        else if (tok == OTA_FDT_PROP) {
            if (pos + 8 > size_struct)
                return -1;
            len = be32(fdt + off_struct + pos);
            nameoff = be32(fdt + off_struct + pos + 4);
            pos += 8;
            if (len > size_struct - pos || nameoff >= total - off_str)
                return -1;
            pname = (const char *)(fdt + off_str + nameoff);
            if (len == 4 && strncmp(pname, name, total - off_str - nameoff)
                    == 0) {
                *val = be32(fdt + off_struct + pos);
                return 0;
            }
            pos = (pos + len + 3) & ~3U;
        }
        else if (tok == OTA_FDT_END) {
            break;
        }
        else if (tok != OTA_FDT_END_NODE && tok != OTA_FDT_NOP) {
            return -1;
        }
    }
    return -1;
}

static uint32_t part_base(int part)
{
    return (part == PART_BOOT) ? WOLFBOOT_PARTITION_BOOT_ADDRESS :
                                 WOLFBOOT_PARTITION_UPDATE_ADDRESS;
}

static int part_invalidate(int part)
{
    uint32_t base = part_base(part);
    int ret;

    ext_flash_unlock();
    ret = ext_flash_erase(base, WOLFBOOT_SECTOR_SIZE);
    if (ret == 0)
        ret = ext_flash_erase(base + WOLFBOOT_PARTITION_SIZE -
            WOLFBOOT_SECTOR_SIZE, WOLFBOOT_SECTOR_SIZE);
    ext_flash_lock();
    return ret;
}

static void slot_state_print(int part)
{
    uint8_t st = 0;

    uart_puts(part == PART_BOOT ? "OTA: slot A " : "OTA: slot B ");
    if (wolfBoot_get_partition_state((uint8_t)part, &st) != 0)
        uart_puts("no state\n");
    else if (st == IMG_STATE_NEW)
        uart_puts("new\n");
    else if (st == IMG_STATE_UPDATING)
        uart_puts("staged\n");
    else if (st == IMG_STATE_TESTING)
        uart_puts("on probation\n");
    else if (st == IMG_STATE_SUCCESS)
        uart_puts("confirmed\n");
    else
        uart_puts("unknown\n");
}

static void store_init(uint32_t now_ms)
{
    uint32_t part = 0;
    uint8_t st = IMG_STATE_NEW;
    int other;

    store_ready = 1;
    store_t0 = now_ms;
    uart_puts("OTA: firmware version "); uart_putdec(OTA_APP_VERSION);
    if (fdt_find_u32((const uint8_t *)(uintptr_t)boot_arg0,
            "wolfboot,boot-part", &part) != 0 || part > PART_UPDATE) {
        uart_puts(", not booted by wolfBoot: updates disabled\n");
        return;
    }
    store_part = (int)part;
    other = store_part ^ 1;
    uart_puts(", slot "); uart_puts(store_part == PART_BOOT ? "A" : "B");
    uart_puts("\n");

    hal_init();
    slot_state_print(PART_BOOT);
    slot_state_print(PART_UPDATE);

    if (wolfBoot_get_partition_state((uint8_t)store_part, &st) == 0 &&
            st == IMG_STATE_TESTING) {
#ifdef OTA_NEVER_CONFIRM
        uart_puts("OTA: on probation, NOT confirming (demo build)\n");
#else
        store_probation = 1;
#endif
    }
    /* An update still marked as staged or on probation in the other slot
     * was refused by wolfBoot: drop it so it is not retried every boot. */
    st = IMG_STATE_NEW;
    if (wolfBoot_get_partition_state((uint8_t)other, &st) == 0 &&
            (st == IMG_STATE_UPDATING || st == IMG_STATE_TESTING)) {
        uart_puts("OTA: previous update was rejected, clearing slot ");
        uart_puts(other == PART_BOOT ? "A\n" : "B\n");
        (void)part_invalidate(other);
    }
}

int ota_store_on_probation(void)
{
    return store_probation;
}

void ota_store_confirm(void)
{
    if (!store_probation)
        return;
    wolfBoot_success_part((uint8_t)store_part);
    store_probation = 0;
    uart_puts("OTA: update confirmed\n");
}

void ota_store_poll(uint32_t now_ms)
{
    if (!store_ready)
        store_init(now_ms);
#ifdef OTA_NEVER_CONFIRM
    if (store_part >= 0 && (now_ms - store_t0) > OTA_NEVER_CONFIRM_MS) {
        uart_puts("OTA: resetting without confirming\n");
        ota_system_reset();
    }
#endif
}

int ota_store_write(const uint8_t *img, uint32_t len)
{
    static uint8_t chk[4096];
    uint32_t base, erase_len, off, n;
    int target;

    if (store_part < 0 || img == NULL || len == 0 ||
            len > WOLFBOOT_PARTITION_SIZE - WOLFBOOT_SECTOR_SIZE) {
        uart_puts("OTA: image does not fit the slot\n");
        return -1;
    }
    target = store_part ^ 1;
    base = part_base(target);
    erase_len = (len + WOLFBOOT_SECTOR_SIZE - 1) &
        ~((uint32_t)WOLFBOOT_SECTOR_SIZE - 1);

    uart_puts("OTA: writing "); uart_putdec(len);
    uart_puts(" bytes to slot "); uart_puts(target == PART_BOOT ? "A" : "B");
    uart_puts("\n");
    ext_flash_unlock();
    if (ext_flash_erase(base, (int)erase_len) != 0 ||
            ext_flash_erase(base + WOLFBOOT_PARTITION_SIZE -
                WOLFBOOT_SECTOR_SIZE, WOLFBOOT_SECTOR_SIZE) != 0 ||
            ext_flash_write(base, img, (int)len) != 0) {
        ext_flash_lock();
        uart_puts("OTA: flash write failed\n");
        return -1;
    }
    for (off = 0; off < len; off += n) {
        n = len - off;
        if (n > sizeof(chk))
            n = sizeof(chk);
        if (ext_flash_read(base + off, chk, (int)n) != (int)n ||
                memcmp(chk, img + off, n) != 0) {
            ext_flash_lock();
            uart_puts("OTA: read-back mismatch\n");
            return -1;
        }
    }
    ext_flash_lock();
    wolfBoot_update_trigger_part((uint8_t)target);
    uart_puts("OTA: update staged, marked for probation\n");
    return 0;
}

static uint64_t smc_call(uint64_t fid, uint64_t a1, uint64_t a2)
{
    register uint64_t x0 __asm__("x0") = fid;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;

    __asm__ volatile ("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2) : :
        "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
        "x13", "x14", "x15", "x16", "x17");
    return x0;
}

/* System reset through BL31: PSCI SYSTEM_RESET, then the platform
 * management shutdown call (reset, whole system) if that returns. */
void ota_system_reset(void)
{
    uint64_t r;

    uart_puts("OTA: resetting\n");
    r = smc_call(0x84000009U, 0, 0);
    uart_puts("OTA: PSCI reset returned "); uart_puthex((uint32_t)r);
    uart_puts("\n");
    r = smc_call(0xC200000CU, ((uint64_t)2 << 32) | 1U, 0);
    uart_puts("OTA: PM shutdown returned "); uart_puthex((uint32_t)r);
    uart_puts("\n");
    for (;;)
        ;
}
