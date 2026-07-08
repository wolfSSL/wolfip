# wolfIP RTL8735B (AmebaPro2) Ethernet example -- RealTek FreeRTOS SDK wiring.
#
# Install at <SDK>/component/example/wolfip_eth/ (the wolfip_cycle.sh helper
# copies main.c, user_settings.h and this .cmake there), then select with:
#   cmake .. -DEXAMPLE=wolfip_eth -DWOLFIP_ROOT=/path/to/wolfip \
#            -DWOLFSSL_ROOT=/path/to/wolfssl ...
# (also copy main.c to <SDK>/project/realtek_amebapro2_v0_example/src/main.c)
#
# Adds the wolfIP stack + the RTL8735B MAC glue to the SDK app build. When
# ENABLE_TLS_CLIENT is set it also pulls the wolfSSL TLS layer + the wolfIP TLS
# client. Set -DWOLFIP_ENABLE_TLS=ON to build the TLS-client demo (milestone 2);
# the default is the echo/DHCP demo (milestone 1).

### ---- wolfIP root ---- ###
if(NOT DEFINED WOLFIP_ROOT OR WOLFIP_ROOT STREQUAL "")
    if(DEFINED ENV{WOLFIP_ROOT})
        set(WOLFIP_ROOT $ENV{WOLFIP_ROOT})
    else()
        set(WOLFIP_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../../../wolfip)
    endif()
endif()
if(NOT EXISTS "${WOLFIP_ROOT}/src/wolfip.c")
    message(FATAL_ERROR
        "WOLFIP_ROOT='${WOLFIP_ROOT}' is not a wolfIP tree. "
        "Pass -DWOLFIP_ROOT=/path/to/wolfip.")
endif()
message(STATUS "wolfIP RTL8735B example: WOLFIP_ROOT=${WOLFIP_ROOT}")

set(WOLFIP_PORT_DIR ${WOLFIP_ROOT}/src/port/rtl8735b)

### ---- header search paths (example dir first so our config.h wins) ---- ###
list(APPEND app_example_inc_path
    ${CMAKE_CURRENT_LIST_DIR}     # user_settings.h (this example dir)
    ${WOLFIP_PORT_DIR}            # config.h, rtl8735b_eth.h, tls_client.h
    ${WOLFIP_ROOT}               # wolfip.h
)

### ---- wolfIP compile definitions ---- ###
# The SDK's lwIP posix-compat layer puts a foreign <sys/socket.h> on the include
# path; tell wolfIP to skip probing for system socket headers and use its own
# POSIX type fallbacks (avoids iovec/msghdr redefinition and a send() macro).
list(APPEND app_example_flags
    WOLFIP_NO_SYS_HEADERS
)

### ---- wolfIP core + RTL8735B MAC glue ---- ###
list(APPEND app_example_sources
    ${WOLFIP_ROOT}/src/wolfip.c
    ${WOLFIP_PORT_DIR}/wolfip_rtl8735b.c
)

### ---- optional TLS client (milestone 2) ---- ###
option(WOLFIP_ENABLE_TLS "Build the wolfIP TLS-client demo" OFF)
if(WOLFIP_ENABLE_TLS)
    if(NOT DEFINED WOLFSSL_ROOT OR WOLFSSL_ROOT STREQUAL "")
        if(DEFINED ENV{WOLFSSL_ROOT})
            set(WOLFSSL_ROOT $ENV{WOLFSSL_ROOT})
        else()
            set(WOLFSSL_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../../../wolfssl)
        endif()
    endif()
    if(NOT EXISTS "${WOLFSSL_ROOT}/wolfcrypt/src/aes.c")
        message(FATAL_ERROR
            "WOLFSSL_ROOT='${WOLFSSL_ROOT}' is not a wolfSSL tree. "
            "Pass -DWOLFSSL_ROOT=/path/to/wolfssl.")
    endif()
    message(STATUS "wolfIP RTL8735B example: TLS on, WOLFSSL_ROOT=${WOLFSSL_ROOT}")

    list(APPEND app_example_inc_path ${WOLFSSL_ROOT})
    list(APPEND app_example_flags WOLFSSL_USER_SETTINGS ENABLE_TLS_CLIENT)

    list(APPEND app_example_sources
        # --- wolfIP TLS glue + client ---
        ${WOLFIP_ROOT}/src/port/wolfssl_io.c
        ${WOLFIP_PORT_DIR}/tls_client.c
        # --- wolfCrypt ---
        ${WOLFSSL_ROOT}/wolfcrypt/src/aes.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/sha256.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/sha512.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/sha.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/hash.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/hmac.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/kdf.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/random.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/memory.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/wc_port.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/error.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/logging.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/wc_encrypt.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/ecc.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/asn.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/coding.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/sp_int.c
        ${WOLFSSL_ROOT}/wolfcrypt/src/wolfmath.c
        # --- wolfSSL TLS layer ---
        ${WOLFSSL_ROOT}/src/internal.c
        ${WOLFSSL_ROOT}/src/keys.c
        ${WOLFSSL_ROOT}/src/tls.c
        ${WOLFSSL_ROOT}/src/tls13.c
        ${WOLFSSL_ROOT}/src/wolfio.c
        ${WOLFSSL_ROOT}/src/ssl.c
        ${WOLFSSL_ROOT}/src/ssl_load.c
        ${WOLFSSL_ROOT}/src/ssl_certman.c
        ${WOLFSSL_ROOT}/src/ssl_misc.c
        ${WOLFSSL_ROOT}/src/ssl_sess.c
        ${WOLFSSL_ROOT}/src/ssl_asn1.c
        ${WOLFSSL_ROOT}/src/ssl_crypto.c
        ${WOLFSSL_ROOT}/src/x509.c
        ${WOLFSSL_ROOT}/src/x509_str.c
    )
endif()
