/* cache.h
 *
 * MIPS KSEG segment helpers for DMA-coherent access on PIC32MZ.
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
#ifndef PIC32MZ_CACHE_H
#define PIC32MZ_CACHE_H

#include <stdint.h>

/* The PIC32MZ Ethernet controller (EMAC) is not cache-coherent and programs
 * its descriptor base/buffer pointers with PHYSICAL addresses. The simplest
 * coherent scheme on MIPS is to access all descriptor rings and DMA buffers
 * through KSEG1 (uncached) virtual aliases and hand the EMAC the physical
 * address. This avoids per-operation cache clean/invalidate entirely.
 *
 * Equivalent to XC32 <sys/kmem.h> KVA0_TO_KVA1 / KVA_TO_PA / PA_TO_KVA1, but
 * kept self-contained so the early bare-metal layer can be lifted into
 * wolfBoot without pulling in the XC32 system headers.
 */

/* Cached KSEG0 virtual address -> uncached KSEG1 virtual address */
#define PIC32_KVA0_TO_KVA1(v)   (((uint32_t)(v)) | 0x20000000u)

/* Any KSEG0/KSEG1 virtual address -> physical address (for the EMAC) */
#define PIC32_KVA_TO_PA(v)      (((uint32_t)(v)) & 0x1FFFFFFFu)

/* Physical address -> uncached KSEG1 virtual address */
#define PIC32_PA_TO_KVA1(pa)    (((uint32_t)(pa)) | 0xA0000000u)

/* Pointer helper: uncached view of a normally-allocated object */
#define PIC32_UNCACHED(p)       ((void *)PIC32_KVA0_TO_KVA1(p))

#endif /* PIC32MZ_CACHE_H */
