/* cyw43439_fw.h - accessors for the CYW43439 firmware/CLM/NVRAM blob
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
 * The firmware blob itself is NOT part of this repository - it carries
 * third-party copyright under a license that restricts it to RP silicon.
 * Provide it by placing the vendor headers in the git-ignored fw_local/
 * directory and building fw_local/cyw43_fw_blob.c (the Makefile picks it
 * up automatically when present). When the blob is absent these accessors
 * are weak and return NULL, so the driver reports "no firmware" cleanly
 * instead of failing to link.
 */

#ifndef WOLFIP_CYW43439_FW_H
#define WOLFIP_CYW43439_FW_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Each returns a pointer into flash and writes the length via *len, or
 * returns NULL (and *len = 0) when the blob is not linked in. */
const uint8_t *cyw43_blob_fw(size_t *len);
const uint8_t *cyw43_blob_clm(size_t *len);
const uint8_t *cyw43_blob_nvram(size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_CYW43439_FW_H */
