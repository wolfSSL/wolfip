/* mqtt_broker_persist_flash.c
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
 */

/* STM32H5 internal-flash persistence backend for the wolfMQTT broker.
 *
 * Implements the MqttBrokerPersistHooks key/value API over a reserved
 * 32KB region at the top of internal flash (see target.ld, which shrinks
 * the code FLASH region by 32KB so nothing is linked over the store).
 * The broker codec (mqtt_broker_persist.c) wraps every record in
 * AES-256-GCM before kv_put and unwraps on kv_get/kv_iter; this backend
 * only ever stores and returns opaque ciphertext blobs.
 *
 * On-flash layout (log-structured, two banks for power-safe compaction):
 *
 *   Region = 4x 8KB sectors. Split into bank A (sectors 0-1) and bank B
 *   (sectors 2-3), 16KB each. Exactly one bank is "active" at a time;
 *   the other is the compaction target.
 *
 *   Each bank begins with a 16-byte bank header (magic "BNK1" + a 32-bit
 *   generation counter). The active bank is the valid bank with the
 *   highest generation. Records are appended after the header.
 *
 *   Record (every field 16-byte aligned to honor the H5 128-bit program
 *   quantum + per-quad-word ECC, which forbids re-programming a written
 *   quad-word between erases):
 *
 *     +0   header   QW : "REC1" | ns | rsvd | key_len(2) | blob_len(4) |
 *                        stride(4)
 *     +16  commit   QW : byte0 == 0xC5 once the record is fully written
 *                        (erased 0xFF == torn/uncommitted)
 *     +32  payload     : key bytes || blob bytes, padded with 0xFF to a
 *                        16-byte boundary
 *     +..  tombstone QW: erased 0xFF == live; byte0 programmed to 0x00 to
 *                        delete (a separate, still-erased quad-word, so a
 *                        delete never re-programs the header/commit/data)
 *
 *   "Latest committed record wins" per (ns,key): kv_put just appends a
 *   new committed record (shadowing older ones); kv_del tombstones the
 *   latest committed record; kv_get / kv_iter resolve each key to its
 *   last committed record and treat a tombstoned latest as absent. When
 *   the active bank cannot fit a new record, compaction copies the
 *   latest live record of every key into the freshly-erased other bank,
 *   commits it by writing the new bank header (higher generation), then
 *   erases the old bank. A crash before the new header is written leaves
 *   the old bank intact and authoritative.
 *
 * The KV region lives in flash bank 2 (>= 0x08100000) while code runs
 * from bank 1, so erase/program of the region does not stall instruction
 * fetch (cross-bank), and no RAMFUNCTION is required.
 *
 * TZEN=0 only: writes flash via the non-secure FLASH register view, the
 * same as tftp_client_demo.c.
 */

#include "mqtt_broker_persist_flash.h"

#ifdef WOLFMQTT_BROKER_PERSIST

#include <wolfmqtt/mqtt_client.h>   /* MQTT_CODE_ERROR_* */
#include <stdint.h>
#include <string.h>

/* ----- Reserved flash KV region ------------------------------------- *
 * Must match the 32KB carved out of FLASH LENGTH in target.ld. */
#define KVF_REGION_BASE   0x081F8000UL
#define KVF_SECTOR_SIZE   0x2000UL            /* 8KB erase granule */
#define KVF_BANK_SIZE     0x4000UL            /* 2 sectors per bank */
#define KVF_BANK_A        (KVF_REGION_BASE)
#define KVF_BANK_B        (KVF_REGION_BASE + KVF_BANK_SIZE)
#define KVF_REGION_TOP    (KVF_REGION_BASE + 2UL * KVF_BANK_SIZE)

/* ----- Record format constants -------------------------------------- */
#define KVF_QW            16U                 /* quad-word / program unit */
#define KVF_HDR_OFF       0U
#define KVF_COMMIT_OFF    KVF_QW
#define KVF_PAYLOAD_OFF   (2U * KVF_QW)        /* header + commit */
#define KVF_COMMIT_MARK   0xC5U
#define KVF_TOMB_MARK     0x00U

#define KVF_MAX_KEY       256U                 /* per hooks API contract */

/* Largest GCM-wrapped blob the wolfMQTT persist codec can emit, derived
 * from the broker config macros so a config bump cannot silently exceed
 * it. Encrypted blob layout (wolfMQTT src/mqtt_broker_persist.c):
 * WMQB header (12) + GCM nonce (12) + body + GCM tag (16). */
#define KVF_WRAP_OVERHEAD  (12U + 12U + 16U)
/* Largest record bodies the codec can emit:
 * SUBS: 2 + count*(1+1+2+filter), count <= BROKER_MAX_SUBS,
 *       filter strlen <= BROKER_MAX_FILTER_LEN-1
 * OUTQ: 26 + topic + payload (covers RETAINED, which is 6 smaller;
 *       OUTQ itself is a no-op under WOLFMQTT_STATIC_MEMORY but
 *       keeping it in the bound makes it config-proof) */
#define KVF_SUBS_BODY_MAX  (2U + (BROKER_MAX_SUBS) * \
                            (4U + (BROKER_MAX_FILTER_LEN - 1U)))
#define KVF_OUTQ_BODY_MAX  (26U + (BROKER_MAX_TOPIC_LEN - 1U) + \
                            (BROKER_MAX_PAYLOAD_LEN))
#define KVF_BODY_MAX       ((KVF_SUBS_BODY_MAX > KVF_OUTQ_BODY_MAX) ? \
                            KVF_SUBS_BODY_MAX : KVF_OUTQ_BODY_MAX)
#define KVF_MAX_BLOB       (KVF_BODY_MAX + KVF_WRAP_OVERHEAD)

#define KVF_PAYLOAD_PAD_MAX  (((KVF_MAX_KEY + KVF_MAX_BLOB) + 15U) & ~15U)

#define KVF_ALIGN16(x)    (((uint32_t)(x) + 15U) & ~15U)
/* stride = header + commit + padded payload + tombstone */
#define KVF_STRIDE(klen, blen)  (3U * KVF_QW + KVF_ALIGN16((klen) + (blen)))

/* One max-size record (plus the bank header quad-word) must fit in a
 * bank, or kv_put could never store it even after compaction. */
typedef char kvf_assert_rec_fits_bank[
    (KVF_STRIDE(KVF_MAX_KEY, KVF_MAX_BLOB) + KVF_QW <= KVF_BANK_SIZE) ?
    1 : -1];

/* ----- STM32H5 FLASH controller (TZEN=0 / non-secure view) ---------- */
#define KVF_FLASH_BASE       0x40022000UL
#define KVF_FLASH_KEYR       (*(volatile uint32_t *)(KVF_FLASH_BASE + 0x04))
#define KVF_FLASH_SR         (*(volatile uint32_t *)(KVF_FLASH_BASE + 0x20))
#define KVF_FLASH_CR         (*(volatile uint32_t *)(KVF_FLASH_BASE + 0x28))
#define KVF_FLASH_CCR        (*(volatile uint32_t *)(KVF_FLASH_BASE + 0x30))
#define KVF_FLASH_OPTSR_CUR  (*(volatile uint32_t *)(KVF_FLASH_BASE + 0x50))

#define KVF_FLASH_KEY1       0x45670123UL
#define KVF_FLASH_KEY2       0xCDEF89ABUL

#define KVF_FLASH_CR_LOCK    (1U << 0)
#define KVF_FLASH_CR_PG      (1U << 1)
#define KVF_FLASH_CR_SER     (1U << 2)
#define KVF_FLASH_CR_BER     (1U << 3)
#define KVF_FLASH_CR_STRT    (1U << 5)
#define KVF_FLASH_CR_PNB_SHIFT 6
#define KVF_FLASH_CR_PNB_MASK  0x7FU
#define KVF_FLASH_CR_MER     (1U << 15)
#define KVF_FLASH_CR_BKSEL   (1U << 31)

#define KVF_FLASH_SR_BSY     (1U << 0)
#define KVF_FLASH_CCR_CLR_ALL  (0x7FE0001FU)
#define KVF_FLASH_SR_ERR_MASK  (0x07FE0000U)
#define KVF_FLASH_OPTSR_SWAP   (1U << 31)

#define KVF_FLASH_PAGE_SIZE  0x2000UL
#define KVF_FLASH_BANK2_BASE 0x08100000UL
#define KVF_FLASH_TOP        0x081FFFFFUL
#define KVF_FLASH_BASE_ADDR  0x08000000UL

/* ----- Backend context (lives in hooks->ctx) ------------------------ */
typedef struct KvfCtx {
    uint32_t active_base;   /* flash addr of active bank header */
    uint32_t append_off;    /* offset within active bank for next record */
    uint32_t generation;    /* active bank generation */
    int      ready;
} KvfCtx;

/* A parsed view of one on-flash record. key/blob point into mapped flash. */
typedef struct KvfRec {
    uint32_t    addr;       /* flash addr of record header */
    uint32_t    stride;
    const byte* key;
    const byte* blob;
    word32      blob_len;
    word16      key_len;
    byte        ns;
    byte        committed;
    byte        tombstoned;
} KvfRec;

static KvfCtx g_kvf;
/* Staging buffer for one record payload. No malloc (WOLFMQTT_STATIC_MEMORY). */
static byte   g_kvf_payload[KVF_PAYLOAD_PAD_MAX];

/* ----- Little-endian helpers ---------------------------------------- */
static void kvf_put16(byte* p, word16 v)
{
    p[0] = (byte)(v & 0xFF);
    p[1] = (byte)((v >> 8) & 0xFF);
}
static void kvf_put32(byte* p, word32 v)
{
    p[0] = (byte)(v & 0xFF);
    p[1] = (byte)((v >> 8) & 0xFF);
    p[2] = (byte)((v >> 16) & 0xFF);
    p[3] = (byte)((v >> 24) & 0xFF);
}
static word16 kvf_get16(const byte* p)
{
    return (word16)((word16)p[0] | ((word16)p[1] << 8));
}
static word32 kvf_get32(const byte* p)
{
    return (word32)p[0] | ((word32)p[1] << 8) |
           ((word32)p[2] << 16) | ((word32)p[3] << 24);
}

/* ----- Flash HAL (adapted from tftp_client_demo.c, TZEN=0) ---------- */
static void kvf_flash_wait(void)
{
    while ((KVF_FLASH_SR & KVF_FLASH_SR_BSY) != 0)
        ;
}

static void kvf_flash_unlock(void)
{
    kvf_flash_wait();
    if ((KVF_FLASH_CR & KVF_FLASH_CR_LOCK) != 0) {
        KVF_FLASH_KEYR = KVF_FLASH_KEY1;
        KVF_FLASH_KEYR = KVF_FLASH_KEY2;
        while ((KVF_FLASH_CR & KVF_FLASH_CR_LOCK) != 0)
            ;
    }
}

static void kvf_flash_lock(void)
{
    kvf_flash_wait();
    if ((KVF_FLASH_CR & KVF_FLASH_CR_LOCK) == 0)
        KVF_FLASH_CR |= KVF_FLASH_CR_LOCK;
}

/* Erase the 8KB sector covering `addr`. addr must be sector-aligned.
 * Assumes the flash is already unlocked. */
static int kvf_flash_erase_sector(uint32_t addr)
{
    uint32_t reg;
    uint32_t bnksel = 0;
    uint32_t base = KVF_FLASH_BASE_ADDR;

    if (addr < KVF_FLASH_BASE_ADDR || addr > KVF_FLASH_TOP)
        return -1;
    if (addr >= KVF_FLASH_BANK2_BASE) {
        base = KVF_FLASH_BANK2_BASE;
        bnksel = 1;
    }
    if (((KVF_FLASH_OPTSR_CUR & KVF_FLASH_OPTSR_SWAP) >> 31) != 0)
        bnksel = bnksel ? 0 : 1;

    KVF_FLASH_CCR = KVF_FLASH_CCR_CLR_ALL;
    reg = KVF_FLASH_CR & ~((KVF_FLASH_CR_PNB_MASK << KVF_FLASH_CR_PNB_SHIFT) |
        KVF_FLASH_CR_SER | KVF_FLASH_CR_BER | KVF_FLASH_CR_PG |
        KVF_FLASH_CR_MER | KVF_FLASH_CR_BKSEL);
    reg |= (((addr - base) >> 13) << KVF_FLASH_CR_PNB_SHIFT) | KVF_FLASH_CR_SER |
        (bnksel ? KVF_FLASH_CR_BKSEL : 0U);
    KVF_FLASH_CR = reg;
    __asm volatile ("isb");
    KVF_FLASH_CR |= KVF_FLASH_CR_STRT;
    kvf_flash_wait();
    KVF_FLASH_CR &= ~KVF_FLASH_CR_SER;
    if ((KVF_FLASH_SR & KVF_FLASH_SR_ERR_MASK) != 0) {
        KVF_FLASH_CCR = KVF_FLASH_CCR_CLR_ALL;
        return -1;
    }
    return 0;
}

/* Program one 128-bit (16-byte) quad-word at addr (16-byte aligned).
 * Assumes the flash is already unlocked. `qw` is a 16-byte buffer. */
static int kvf_flash_program_qword(uint32_t addr, const byte* qw)
{
    volatile uint32_t *dst;
    uint32_t buf[4];
    int i;

    if ((addr & 0xFU) != 0)
        return -1;
    KVF_FLASH_CCR = KVF_FLASH_CCR_CLR_ALL;
    for (i = 0; i < 16; i++)
        ((byte *)buf)[i] = qw[i];
    dst = (volatile uint32_t *)addr;
    KVF_FLASH_CR |= KVF_FLASH_CR_PG;
    for (i = 0; i < 4; i++) {
        dst[i] = buf[i];
        __asm volatile ("isb");
    }
    kvf_flash_wait();
    {
        uint32_t sr = KVF_FLASH_SR;
        KVF_FLASH_CCR = KVF_FLASH_CCR_CLR_ALL;
        KVF_FLASH_CR &= ~KVF_FLASH_CR_PG;
        if ((sr & KVF_FLASH_SR_ERR_MASK) != 0)
            return -1;
    }
    return 0;
}

/* Erase both sectors of a bank. Assumes unlocked. */
static int kvf_erase_bank(uint32_t bank_base)
{
    if (kvf_flash_erase_sector(bank_base) != 0)
        return -1;
    if (kvf_flash_erase_sector(bank_base + KVF_SECTOR_SIZE) != 0)
        return -1;
    return 0;
}

/* Direct read from memory-mapped flash. Must not run concurrently with a
 * program/erase on the same bank; all callers read while flash is idle. */
static void kvf_read(uint32_t addr, byte* dst, uint32_t len)
{
    memcpy(dst, (const void *)(uintptr_t)addr, len);
}

static int kvf_qw_is_erased(uint32_t addr)
{
    byte tmp[KVF_QW];
    int i;
    kvf_read(addr, tmp, KVF_QW);
    for (i = 0; i < (int)KVF_QW; i++) {
        if (tmp[i] != 0xFF)
            return 0;
    }
    return 1;
}

/* ----- Bank header -------------------------------------------------- */
static int kvf_write_bank_header(uint32_t bank_base, uint32_t gen)
{
    byte qw[KVF_QW];
    memset(qw, 0xFF, sizeof(qw));
    qw[0] = 'B'; qw[1] = 'N'; qw[2] = 'K'; qw[3] = '1';
    kvf_put32(&qw[4], gen);
    return kvf_flash_program_qword(bank_base, qw);
}

/* Returns 1 and sets *gen if a valid bank header is present, else 0. */
static int kvf_bank_gen(uint32_t bank_base, uint32_t* gen)
{
    byte hdr[KVF_QW];
    kvf_read(bank_base, hdr, sizeof(hdr));
    if (hdr[0] != 'B' || hdr[1] != 'N' || hdr[2] != 'K' || hdr[3] != '1')
        return 0;
    if (gen != NULL)
        *gen = kvf_get32(&hdr[4]);
    return 1;
}

/* ----- Record parse ------------------------------------------------- *
 * Returns 1 on a valid record, 0 on an empty (erased) slot (end of log),
 * -1 on corruption. */
static int kvf_rec_parse(uint32_t addr, uint32_t bank_end, KvfRec* r)
{
    byte hdr[KVF_QW];
    word16 key_len;
    word32 blob_len;
    uint32_t stride;
    uint32_t pay_off;

    if (addr + KVF_QW > bank_end)
        return 0;
    if (kvf_qw_is_erased(addr))
        return 0;
    kvf_read(addr, hdr, sizeof(hdr));
    if (hdr[0] != 'R' || hdr[1] != 'E' || hdr[2] != 'C' || hdr[3] != '1')
        return -1;
    key_len = kvf_get16(&hdr[6]);
    blob_len = kvf_get32(&hdr[8]);
    stride = kvf_get32(&hdr[12]);
    if (key_len == 0 || key_len > KVF_MAX_KEY || blob_len > KVF_MAX_BLOB)
        return -1;
    if (stride != KVF_STRIDE(key_len, blob_len))
        return -1;
    if (addr + stride > bank_end)
        return -1;

    pay_off = KVF_PAYLOAD_OFF;
    r->addr = addr;
    r->stride = stride;
    r->ns = hdr[4];
    r->key_len = key_len;
    r->blob_len = blob_len;
    r->key = (const byte *)(uintptr_t)(addr + pay_off);
    r->blob = (const byte *)(uintptr_t)(addr + pay_off + key_len);
    {
        byte cb[KVF_QW];
        uint32_t tomb_addr = addr + pay_off + KVF_ALIGN16(key_len + blob_len);
        kvf_read(addr + KVF_COMMIT_OFF, cb, sizeof(cb));
        r->committed = (cb[0] == KVF_COMMIT_MARK) ? 1 : 0;
        kvf_read(tomb_addr, cb, sizeof(cb));
        r->tombstoned = (cb[0] == KVF_TOMB_MARK) ? 1 : 0;
    }
    return 1;
}

static int kvf_key_eq(const KvfRec* r, byte ns, const byte* key,
    word16 key_len)
{
    if (r->ns != ns || r->key_len != key_len)
        return 0;
    return (memcmp(r->key, key, key_len) == 0) ? 1 : 0;
}

/* Find the latest committed record matching (ns,key) in `bank_base`.
 * Returns 1 and fills *out if found, else 0. */
static int kvf_lookup_latest(uint32_t bank_base, byte ns, const byte* key,
    word16 key_len, KvfRec* out)
{
    uint32_t off = KVF_QW;
    uint32_t end = bank_base + KVF_BANK_SIZE;
    KvfRec r;
    int found = 0;

    while (bank_base + off < end) {
        int rc = kvf_rec_parse(bank_base + off, end, &r);
        if (rc <= 0)
            break;
        if (r.committed && kvf_key_eq(&r, ns, key, key_len)) {
            *out = r;
            found = 1;
        }
        off += r.stride;
    }
    return found;
}

/* Is `rec` the latest committed record for its key (no later committed
 * record shares the same ns+key)? */
static int kvf_is_latest(uint32_t bank_base, const KvfRec* rec)
{
    uint32_t off = (rec->addr - bank_base) + rec->stride;
    uint32_t end = bank_base + KVF_BANK_SIZE;
    KvfRec r;

    while (bank_base + off < end) {
        int rc = kvf_rec_parse(bank_base + off, end, &r);
        if (rc <= 0)
            break;
        if (r.committed && kvf_key_eq(&r, rec->ns, rec->key, rec->key_len))
            return 0;
        off += r.stride;
    }
    return 1;
}

/* Append a fully-formed committed record at bank_base+off. Assumes the
 * flash is unlocked. key/blob may point into mapped flash; they are
 * copied into RAM before any program so no flash read overlaps a program
 * on the same bank. The commit quad-word is written last. */
static int kvf_append_record(uint32_t bank_base, uint32_t off, byte ns,
    const byte* key, word16 key_len, const byte* blob, word32 blob_len)
{
    uint32_t addr = bank_base + off;
    uint32_t pad = KVF_ALIGN16(key_len + blob_len);
    uint32_t i;
    byte qw[KVF_QW];

    /* Stage payload in RAM first (source reads complete before programming). */
    memset(g_kvf_payload, 0xFF, pad);
    memcpy(g_kvf_payload, key, key_len);
    memcpy(g_kvf_payload + key_len, blob, blob_len);

    /* Header */
    memset(qw, 0xFF, sizeof(qw));
    qw[0] = 'R'; qw[1] = 'E'; qw[2] = 'C'; qw[3] = '1';
    qw[4] = ns;
    kvf_put16(&qw[6], key_len);
    kvf_put32(&qw[8], blob_len);
    kvf_put32(&qw[12], KVF_STRIDE(key_len, blob_len));
    if (kvf_flash_program_qword(addr + KVF_HDR_OFF, qw) != 0)
        return -1;

    /* Payload */
    for (i = 0; i < pad; i += KVF_QW) {
        if (kvf_flash_program_qword(addr + KVF_PAYLOAD_OFF + i,
                g_kvf_payload + i) != 0)
            return -1;
    }

    /* Commit (last) */
    memset(qw, 0xFF, sizeof(qw));
    qw[0] = KVF_COMMIT_MARK;
    if (kvf_flash_program_qword(addr + KVF_COMMIT_OFF, qw) != 0)
        return -1;

    return 0;
}

/* Tombstone a committed record by programming its (still-erased)
 * tombstone quad-word. Assumes flash unlocked. */
static int kvf_write_tombstone(const KvfRec* rec)
{
    uint32_t tomb_addr = rec->addr + KVF_PAYLOAD_OFF +
        KVF_ALIGN16(rec->key_len + rec->blob_len);
    byte qw[KVF_QW];
    memset(qw, 0xFF, sizeof(qw));
    qw[0] = KVF_TOMB_MARK;
    return kvf_flash_program_qword(tomb_addr, qw);
}

/* Compact the active bank into the other bank, keeping only the latest
 * live record per key. Updates g_kvf on success. Assumes flash unlocked. */
static int kvf_compact(void)
{
    uint32_t src = g_kvf.active_base;
    uint32_t dst = (src == KVF_BANK_A) ? KVF_BANK_B : KVF_BANK_A;
    uint32_t end = src + KVF_BANK_SIZE;
    uint32_t off = KVF_QW;
    uint32_t toff = KVF_QW;
    KvfRec r;

    if (kvf_erase_bank(dst) != 0)
        return MQTT_CODE_ERROR_SYSTEM;

    while (src + off < end) {
        int rc = kvf_rec_parse(src + off, end, &r);
        if (rc <= 0)
            break;
        if (r.committed && !r.tombstoned && kvf_is_latest(src, &r)) {
            if (toff + r.stride > KVF_BANK_SIZE)
                return MQTT_CODE_ERROR_OUT_OF_BUFFER;
            if (kvf_append_record(dst, toff, r.ns, r.key, r.key_len,
                    r.blob, r.blob_len) != 0)
                return MQTT_CODE_ERROR_SYSTEM;
            toff += r.stride;
        }
        off += r.stride;
    }

    /* Commit the new bank by writing its header (higher generation). A
     * crash before this leaves the old bank authoritative. */
    if (kvf_write_bank_header(dst, g_kvf.generation + 1) != 0)
        return MQTT_CODE_ERROR_SYSTEM;
    (void)kvf_erase_bank(src);

    g_kvf.active_base = dst;
    g_kvf.generation += 1;
    g_kvf.append_off = toff;
    return 0;
}

/* ----- Hook callbacks ----------------------------------------------- */
static int kvf_put(void* ctx, byte ns, const byte* key, word16 key_len,
    const byte* blob, word32 blob_len)
{
    KvfCtx* c = (KvfCtx*)ctx;
    uint32_t stride;
    int rc;

    if (c == NULL || !c->ready || key == NULL || blob == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;
    if (key_len == 0 || key_len > KVF_MAX_KEY || blob_len > KVF_MAX_BLOB)
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;

    stride = KVF_STRIDE(key_len, blob_len);
    if (c->append_off + stride > KVF_BANK_SIZE) {
        kvf_flash_unlock();
        rc = kvf_compact();
        if (rc == 0 && (c->append_off + stride > KVF_BANK_SIZE))
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        if (rc != 0) {
            kvf_flash_lock();
            return rc;
        }
    }
    else {
        kvf_flash_unlock();
    }

    rc = kvf_append_record(c->active_base, c->append_off, ns, key, key_len,
        blob, blob_len);
    if (rc == 0)
        c->append_off += stride;
    kvf_flash_lock();
    return (rc == 0) ? 0 : MQTT_CODE_ERROR_SYSTEM;
}

static int kvf_get(void* ctx, byte ns, const byte* key, word16 key_len,
    byte* out, word32* inout_len)
{
    KvfCtx* c = (KvfCtx*)ctx;
    KvfRec r;

    if (c == NULL || !c->ready || key == NULL || inout_len == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    if (!kvf_lookup_latest(c->active_base, ns, key, key_len, &r) ||
            r.tombstoned) {
        *inout_len = 0;
        return MQTT_CODE_ERROR_NOT_FOUND;
    }
    if (out == NULL || r.blob_len > *inout_len) {
        *inout_len = r.blob_len;
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    kvf_read((uint32_t)(uintptr_t)r.blob, out, r.blob_len);
    *inout_len = r.blob_len;
    return 0;
}

static int kvf_del(void* ctx, byte ns, const byte* key, word16 key_len)
{
    KvfCtx* c = (KvfCtx*)ctx;
    KvfRec r;
    int rc = 0;

    if (c == NULL || !c->ready || key == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    if (kvf_lookup_latest(c->active_base, ns, key, key_len, &r) &&
            !r.tombstoned) {
        kvf_flash_unlock();
        if (kvf_write_tombstone(&r) != 0)
            rc = MQTT_CODE_ERROR_SYSTEM;
        kvf_flash_lock();
    }
    return rc;
}

static int kvf_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx)
{
    KvfCtx* c = (KvfCtx*)ctx;
    uint32_t off = KVF_QW;
    uint32_t end;
    KvfRec r;

    if (c == NULL || !c->ready || cb == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;
    end = c->active_base + KVF_BANK_SIZE;

    while (c->active_base + off < end) {
        int rc = kvf_rec_parse(c->active_base + off, end, &r);
        if (rc <= 0)
            break;
        if (r.committed && r.ns == ns && !r.tombstoned &&
                kvf_is_latest(c->active_base, &r)) {
            if (cb(r.key, r.key_len, r.blob, r.blob_len, cb_ctx) != 0)
                break;
        }
        off += r.stride;
    }
    return 0;
}

static int kvf_sync(void* ctx)
{
    /* Programs are synchronous: kvf_flash_wait() already blocked until the
     * write completed, so data is durable once kv_put/kv_del returned. */
    (void)ctx;
    return 0;
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
/* Development-only key derivation. NOT FOR PRODUCTION: returns a fixed
 * 32-byte AES-256 key so the encrypted-at-rest round-trip can be tested
 * without a key store / secure element. Matches the fixed pattern used by
 * the upstream CLI dev hook (src/mqtt_broker.c). A real deployment must
 * replace this with a key derived from an SE/HSM or device-unique secret. */
static int kvf_derive_key(void* ctx, byte* out_key, word32 key_len)
{
    word32 i;
    (void)ctx;
    if (out_key == NULL || key_len < 32)
        return MQTT_CODE_ERROR_BAD_ARG;
    for (i = 0; i < key_len; i++)
        out_key[i] = (byte)(0xA0 + (i & 0x0F));
    return 0;
}
#endif

/* ----- Region recovery / format ------------------------------------- */
/* Scan a bank for the append offset (first erased slot). Returns the
 * offset for the next append. On detecting a corrupt record it sets
 * *corrupt=1 and returns KVF_QW; the caller treats *corrupt as the signal
 * (the returned offset is meaningless in that case) and reformats. */
static uint32_t kvf_scan_append(uint32_t bank_base, int* corrupt)
{
    uint32_t off = KVF_QW;
    uint32_t end = bank_base + KVF_BANK_SIZE;
    KvfRec r;

    *corrupt = 0;
    while (bank_base + off < end) {
        int rc = kvf_rec_parse(bank_base + off, end, &r);
        if (rc == 0)
            return off;          /* empty slot: append here */
        if (rc < 0) {
            *corrupt = 1;
            return KVF_QW;
        }
        off += r.stride;
    }
    return off;                  /* bank full (next put compacts) */
}

static int kvf_format(uint32_t bank_base, uint32_t gen)
{
    kvf_flash_unlock();
    if (kvf_erase_bank(bank_base) != 0) {
        kvf_flash_lock();
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (kvf_write_bank_header(bank_base, gen) != 0) {
        kvf_flash_lock();
        return MQTT_CODE_ERROR_SYSTEM;
    }
    kvf_flash_lock();
    return 0;
}

int MqttBrokerNet_PersistFlash_Init(MqttBrokerPersistHooks* hooks)
{
    uint32_t genA = 0, genB = 0;
    int validA, validB;
    int corrupt = 0;
    int rc;

    if (hooks == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    memset(&g_kvf, 0, sizeof(g_kvf));

    validA = kvf_bank_gen(KVF_BANK_A, &genA);
    validB = kvf_bank_gen(KVF_BANK_B, &genB);

    if (!validA && !validB) {
        /* Fresh region: format bank A as generation 1. */
        rc = kvf_format(KVF_BANK_A, 1);
        if (rc != 0)
            return rc;
        g_kvf.active_base = KVF_BANK_A;
        g_kvf.generation = 1;
        g_kvf.append_off = KVF_QW;
    }
    else {
        if (validA && (!validB || genA >= genB)) {
            g_kvf.active_base = KVF_BANK_A;
            g_kvf.generation = genA;
        }
        else {
            g_kvf.active_base = KVF_BANK_B;
            g_kvf.generation = genB;
        }
        g_kvf.append_off = kvf_scan_append(g_kvf.active_base, &corrupt);
        if (corrupt) {
            /* Recover by reformatting the active bank at a higher gen. */
            rc = kvf_format(g_kvf.active_base, g_kvf.generation + 1);
            if (rc != 0)
                return rc;
            g_kvf.generation += 1;
            g_kvf.append_off = KVF_QW;
        }
    }

    g_kvf.ready = 1;

    memset(hooks, 0, sizeof(*hooks));
    hooks->kv_put  = kvf_put;
    hooks->kv_get  = kvf_get;
    hooks->kv_del  = kvf_del;
    hooks->kv_iter = kvf_iter;
    hooks->sync    = kvf_sync;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks->derive_key = kvf_derive_key;
#endif
    hooks->ctx = &g_kvf;
    return 0;
}

#endif /* WOLFMQTT_BROKER_PERSIST */
