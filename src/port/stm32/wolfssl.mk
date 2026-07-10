# wolfssl.mk -- shared wolfSSL/wolfCrypt build plumbing for the STM32 bare-metal
# wolfIP ports (stm32c5a3, stm32h753, stm32h563, ...).
#
# Copyright (C) 2026 wolfSSL Inc.
#
# `include $(ROOT)/src/port/stm32/wolfssl.mk` from a port Makefile. Provides:
#   - WOLFSSL_ROOT / WOLFMQTT_ROOT sibling defaults (a port may set WOLFSSL_ROOT
#     earlier with ?= to point at a worktree; that still wins).
#   - WOLFSSL_SRCS: the minimal wolfSSL/wolfCrypt source set for a TLS 1.3 client
#     (ECC + AES-GCM) plus the ChaCha20-Poly1305 / RSA-verify / logging groups
#     the ports share. Add to SRCS from inside the port's ENABLE_TLS block.
#   - the $(WOLFSSL_ROOT)/%.o relaxed-warning compile rule (uses the port's
#     CFLAGS_WOLFSSL, which the port defines and appends its own -D flags to).
#
# Only variables and a pattern rule live here -- no explicit targets -- so the
# including Makefile keeps ownership of the default goal and of all/clean/size/
# flash. Include it AFTER the port has set CFLAGS (and, if used, its own
# WOLFSSL_ROOT ?= override); the port defines CFLAGS_WOLFSSL itself.

WOLFSSL_ROOT  ?= $(ROOT)/../wolfssl
WOLFMQTT_ROOT ?= $(ROOT)/../wolfmqtt

# Minimal wolfSSL/wolfCrypt source set for a TLS 1.3 client with ECC + AES-GCM.
WOLFSSL_SRCS := \
    $(WOLFSSL_ROOT)/wolfcrypt/src/aes.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sha.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sha512.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/hash.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/kdf.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/random.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/asn.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/coding.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/wc_port.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/memory.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sp_c32.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sp_cortexm.c \
    $(WOLFSSL_ROOT)/src/ssl.c \
    $(WOLFSSL_ROOT)/src/tls.c \
    $(WOLFSSL_ROOT)/src/tls13.c \
    $(WOLFSSL_ROOT)/src/internal.c \
    $(WOLFSSL_ROOT)/src/keys.c \
    $(WOLFSSL_ROOT)/src/wolfio.c

# ChaCha20-Poly1305 (fallback suite).
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/chacha.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/chacha20_poly1305.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/poly1305.c

# RSA for peer certificate verification.
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/rsa.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/signature.c

# Logging / error-strings / encrypt-helpers group. Kept separate because a
# size-tight port may omit it (e.g. with NO_ERROR_STRINGS + logging off). Ports
# that want it do:  WOLFSSL_SRCS += $(WOLFSSL_LOG_SRCS)
WOLFSSL_LOG_SRCS := \
    $(WOLFSSL_ROOT)/wolfcrypt/src/logging.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/error.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/wc_encrypt.c

# wolfSSL objects build with relaxed warnings (third-party, heavily #ifdef'd).
# CFLAGS_WOLFSSL is defined by the including port Makefile. WOLFSSL_EXTRA_DEFS
# lets a port add feature defines that the wolfSSL objects need (e.g. H563's
# -DWOLFSSL_WOLFSSH / -DHAVE_PBKDF2 for its SSH / dot1x builds); it is empty by
# default.
$(WOLFSSL_ROOT)/%.o: $(WOLFSSL_ROOT)/%.c
	$(CC) $(CFLAGS_WOLFSSL) -DWOLFSSL_USER_SETTINGS $(WOLFSSL_EXTRA_DEFS) -I$(WOLFSSL_ROOT) -c $< -o $@
