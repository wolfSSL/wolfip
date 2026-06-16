/* ota.c
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
 * Network-delivered firmware update for the ZCU102 wolfBoot + wolfIP demo.
 *
 * Wires the wolfIP TFTP client (src/tftp/wolftftp.c) to wolfBoot's SD/disk
 * drivers (src/sdhci.c, src/disk.c, src/gpt.c, compiled into this app via
 * the OTA=1 Makefile path). A one-shot RRQ GET stages a newer *signed*
 * image into RAM, writes it to the SD OFP_B partition with disk_part_write(),
 * and resets. wolfBoot then verifies OFP_B's RSA-4096/SHA3 signature and,
 * because the config selects the higher-version image (WOLFBOOT_NO_PARTITIONS),
 * boots the update - with rollback to OFP_A if it ever fails to verify.
 *
 * The image is authenticated by wolfBoot on the next boot, so a tampered or
 * unsigned download simply fails wolfBoot's check and the board falls back
 * to the current image; this module does not itself verify the signature.
 */
#include <stdint.h>
#include <string.h>

#include "wolfip.h"
#include "wolftftp.h"
#include "uart.h"
#include "ota.h"

/* OFP_B (the update slot) - MBR partition index, matches wolfBoot's
 * BOOT_PART_B in zynqmp_sdcard.config. */
#ifndef BOOT_PART_B
#define BOOT_PART_B 2
#endif

/* SD drive number for the disk layer. */
#define OTA_DRIVE 0

/* Largest image we will stage. The signed bare-metal app is well under a
 * megabyte; this cap just bounds the static staging buffer (in DDR .bss).
 * Override with -DOTA_IMG_MAX=... if a larger image is ever needed. */
#ifndef OTA_IMG_MAX
#define OTA_IMG_MAX (8U * 1024U * 1024U)
#endif

/* TFTP tunables. Conservative by default: 512-byte blocks and windowsize 1
 * (one block per ACK) are the most broadly compatible and keep large UDP
 * bursts off the poll-driven GEM RX path. Larger values can be restored once
 * the basic transfer is confirmed. */
#define OTA_LOCAL_PORT   20100U
#define OTA_BLKSIZE      512U
#define OTA_WINDOWSIZE   1U
#define OTA_TIMEOUT_S    2U
#define OTA_MAX_RETRIES  5U
#define OTA_RX_BUF       1500U

/* wolfBoot's disk API (from src/disk.h, compiled in via OTA=1). */
extern int disk_init(int drv);
extern int disk_open(int drv);
extern int disk_part_write(int drv, int part, uint64_t off, uint64_t sz,
    const uint8_t *buf);

/* ---- Module state (single-shot, single transfer) ----------------- */
struct ota_sink {
    uint32_t bytes;        /* bytes staged so far */
    uint8_t  disk_ready;   /* disk_init/open succeeded */
};

static struct wolfIP          *g_stack;
static struct wolftftp_client  g_client;
static int                     g_sock = -1;
static int                     g_started;
static int                     g_done;        /* terminal: reset pending */
static struct ota_sink         g_sink;
static uint8_t                 g_rx_buf[OTA_RX_BUF];

/* Image staging buffer. Plain DDR .bss (write-back cacheable); the SDHCI
 * SDMA coherency is handled by sdhci_platform_dma_prepare/complete in
 * sdhci_shim.c, so this need not be uncached. 64-byte aligned to keep the
 * cache-maintenance ranges tidy. */
static uint8_t g_image[OTA_IMG_MAX] __attribute__((aligned(64)));

/* ---- TFTP io_ops: stage into RAM, then write OFP_B on verify ------ */
/* Bring the SD card up. disk_init() issues a long sequence of SD commands
 * (hundreds of ms). This MUST run before the TFTP transfer starts - doing it
 * inside the open callback blocks the client from ACKing the server's first
 * data block and the transfer times out (-1003). Returns 0 on success. */
static int ota_prepare_disk(void)
{
    int rc;

    g_sink.disk_ready = 0;
    uart_puts("OTA: init SD card...\n");
    rc = disk_init(OTA_DRIVE);
    if (rc < 0) {
        uart_puts("OTA: disk_init failed: "); uart_puthex((uint32_t)rc);
        uart_puts("\n");
        return -1;
    }
    uart_puts("OTA: SD ready, reading MBR...\n");
    rc = disk_open(OTA_DRIVE);
    if (rc < 0) {
        uart_puts("OTA: disk_open (MBR) failed: "); uart_puthex((uint32_t)rc);
        uart_puts("\n");
        return -1;
    }
    g_sink.disk_ready = 1;
    return 0;
}

static int sink_open(void *arg, const char *name, int is_write,
    uint32_t *size_hint, void **handle)
{
    struct ota_sink *s = &g_sink;

    (void)arg;
    (void)name;
    (void)size_hint;
    if (!is_write)
        return WOLFTFTP_ERR_UNSUPPORTED;
    /* SD was brought up in ota_trigger(), before the transfer, so this
     * callback stays fast and the TFTP ACKs are not delayed. */
    if (!s->disk_ready)
        return WOLFTFTP_ERR_IO;

    s->bytes = 0;
    *handle = s;
    uart_puts("OTA: staging update to RAM\n");
    return 0;
}

static int sink_write(void *arg, void *handle, uint32_t offset,
    const uint8_t *buf, uint16_t len)
{
    struct ota_sink *s = (struct ota_sink *)handle;

    (void)arg;
    if (s == NULL || buf == NULL)
        return WOLFTFTP_ERR_IO;
    /* TFTP delivers blocks in order; use the running counter as the write
     * offset and sanity-check it against the reported offset. */
    if (offset != s->bytes)
        return WOLFTFTP_ERR_STATE;
    if ((uint32_t)s->bytes + (uint32_t)len > OTA_IMG_MAX)
        return WOLFTFTP_ERR_SIZE;
    memcpy(&g_image[s->bytes], buf, len);
    /* One dot per 16 KB so progress (or where it stalls) is visible. */
    if (((s->bytes) >> 14) != ((s->bytes + len) >> 14))
        uart_putc('.');
    s->bytes += len;
    return 0;
}

static int sink_hash_update(void *arg, void *handle,
    const uint8_t *buf, uint16_t len)
{
    (void)arg;
    (void)handle;
    (void)buf;
    (void)len;
    /* wolfBoot re-hashes and verifies the RSA-4096/SHA3 signature on the
     * next boot, so no client-side hashing is needed here. */
    return 0;
}

static int sink_verify(void *arg, void *handle, uint32_t total_size)
{
    struct ota_sink *s = (struct ota_sink *)handle;
    int rc;

    (void)arg;
    if (s == NULL || !s->disk_ready)
        return WOLFTFTP_ERR_IO;
    if (total_size != 0 && total_size != s->bytes) {
        uart_puts("OTA: size mismatch vs tsize\n");
        return WOLFTFTP_ERR_VERIFY;
    }

    uart_puts("OTA: writing "); uart_putdec(s->bytes);
    uart_puts(" bytes to OFP_B (part "); uart_putdec(BOOT_PART_B);
    uart_puts(")...\n");
    rc = disk_part_write(OTA_DRIVE, BOOT_PART_B, 0,
        (uint64_t)s->bytes, g_image);
    if (rc < 0) {
        uart_puts("OTA: disk_part_write failed: "); uart_puthex((uint32_t)rc);
        uart_puts("\n");
        return WOLFTFTP_ERR_IO;
    }
    uart_puts("OTA: update staged to OFP_B\n");
    return 0;
}

static void sink_close(void *arg, void *handle, int status)
{
    (void)arg;
    (void)handle;
    (void)status;
}

/* ---- Transport: send via wolfIP UDP socket ------------------------ */
static int ota_udp_send(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct wolfIP_sockaddr_in dst;
    int ret;

    (void)arg;
    (void)local_port;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(remote->port);
    dst.sin_addr.s_addr = ee32(remote->ip);
    ret = wolfIP_sock_sendto(g_stack, g_sock, buf, len, 0,
        (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    if (ret == (int)len)
        return 0;
    return ret < 0 ? ret : -1;
}

/* ---- Public API --------------------------------------------------- */
int ota_trigger(struct wolfIP *stack, uint32_t server_ip_be,
    const char *filename)
{
    struct wolfIP_sockaddr_in bind_addr;
    struct wolftftp_endpoint server_ep;
    struct wolftftp_transport_ops tx;
    struct wolftftp_io_ops io;
    struct wolftftp_transfer_cfg cfg;
    int ret;

    if (stack == NULL || filename == NULL)
        return -1;
    if (g_started)
        return -1;

    g_stack = stack;

    /* Initialize the SD card before starting the transfer (see
     * ota_prepare_disk). Done first so a card error costs no socket. */
    if (ota_prepare_disk() < 0)
        return -1;

    g_sock = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    if (g_sock < 0) {
        uart_puts("OTA: socket() failed\n");
        return -1;
    }
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(OTA_LOCAL_PORT);
    bind_addr.sin_addr.s_addr = 0;
    ret = wolfIP_sock_bind(stack, g_sock,
        (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));
    if (ret < 0) {
        uart_puts("OTA: bind() failed\n");
        wolfIP_sock_close(stack, g_sock);
        g_sock = -1;
        return -1;
    }

    memset(&tx, 0, sizeof(tx));
    tx.send = ota_udp_send;
    tx.arg = NULL;

    memset(&io, 0, sizeof(io));
    io.open = sink_open;
    io.write = sink_write;
    io.hash_update = sink_hash_update;
    io.verify = sink_verify;
    io.close = sink_close;
    io.arg = NULL;

    memset(&cfg, 0, sizeof(cfg));
    cfg.local_port = OTA_LOCAL_PORT;
    cfg.blksize = OTA_BLKSIZE;
    cfg.timeout_s = OTA_TIMEOUT_S;
    cfg.windowsize = OTA_WINDOWSIZE;
    cfg.max_retries = OTA_MAX_RETRIES;
    cfg.max_image_size = OTA_IMG_MAX;

    wolftftp_client_init(&g_client, &tx, &io, &cfg);

    /* wolftftp endpoints carry host-order IPv4; the trigger passes the
     * peer address in network order (sin_addr.s_addr), so swap it. */
    server_ep.ip = ee32(server_ip_be);
    server_ep.port = WOLFTFTP_PORT;
    ret = wolftftp_client_start_rrq(&g_client, &server_ep, filename);
    if (ret != 0) {
        uart_puts("OTA: start_rrq failed: "); uart_puthex((uint32_t)ret);
        uart_puts("\n");
        wolfIP_sock_close(stack, g_sock);
        g_sock = -1;
        return ret;
    }
    g_started = 1;
    uart_puts("OTA: requesting '"); uart_puts(filename);
    uart_puts("' from "); uart_putip4(ee32(server_ip_be)); uart_puts("\n");
    return 0;
}

void ota_poll(struct wolfIP *stack, uint32_t now_ms)
{
    struct wolfIP_sockaddr_in remote;
    uint32_t rlen;
    int n;

    (void)stack;
    if (!g_started || g_sock < 0)
        return;

    for (;;) {
        rlen = sizeof(remote);
        n = wolfIP_sock_recvfrom(g_stack, g_sock, g_rx_buf,
            sizeof(g_rx_buf), 0, (struct wolfIP_sockaddr *)&remote, &rlen);
        if (n <= 0)
            break;
        {
            struct wolftftp_endpoint rep;
            rep.ip = ee32(remote.sin_addr.s_addr);
            rep.port = ee16(remote.sin_port);
            (void)wolftftp_client_receive(&g_client,
                OTA_LOCAL_PORT, &rep, g_rx_buf, (uint16_t)n);
        }
    }
    (void)wolftftp_client_poll(&g_client, now_ms);

    if (g_done)
        return;
    if (g_client.state == WOLFTFTP_CLIENT_COMPLETE) {
        g_done = 1;
        uart_puts("OTA: transfer complete - resetting to apply update\n\n");
        ota_system_reset();
        /* not reached */
    } else if (g_client.state == WOLFTFTP_CLIENT_ERROR) {
        g_done = 1;
        uart_puts("OTA: transfer failed: ");
        uart_puthex((uint32_t)wolftftp_client_status(&g_client));
        /* Diagnostics: how far did it get + what was negotiated. */
        uart_puts("\n  staged=");   uart_putdec(g_sink.bytes);
        uart_puts(" blk=");         uart_putdec(g_client.neg.blksize);
        uart_puts(" win=");         uart_putdec(g_client.neg.windowsize);
        uart_puts(" tsize=");
        uart_putdec(g_client.neg.have_tsize ? g_client.neg.tsize : 0);
        uart_puts("\n  exp_blk=");  uart_putdec(g_client.expected_block);
        uart_puts(" ack_blk=");     uart_putdec(g_client.last_acked_block);
        uart_puts(" retries=");     uart_putdec(g_client.retries);
        uart_puts(" tid_lock=");    uart_putdec(g_client.tid_locked);
        uart_puts(" srv_port=");    uart_putdec(g_client.server.port);
        uart_puts("\n  keeping current image\n");
        wolfIP_sock_close(g_stack, g_sock);
        g_sock = -1;
        g_started = 0;
    }
}

int ota_in_progress(void)
{
    return g_started && !g_done;
}
