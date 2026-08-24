/* Mock wolfcert/types.h for unit tests.
 * Only the transport vtable src/port/wolfcert_io.c implements; the real
 * header needs wolfcert/options.h, which a wolfIP-only build cannot generate.
 */
#ifndef WOLFCERT_TYPES_H
#define WOLFCERT_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pluggable transport, carrying TLS records and plain HTTP alike. */
typedef struct WolfCertTransport {
    /* Return WOLFCERT_OK with the handle stored in *conn, else a negative
     * WOLFCERT_ERR_*. *conn is opaque and never NULL-tested, so 0 is valid. */
    int  (*connect)(void* ctx, const char* host, int port,
                    int timeout_ms, void** conn);
    /* Bytes moved, or a negative WOLFCERT_ERR_*; never 0 (orderly close is
     * CONN_CLOSED). */
    int  (*read)(void* ctx, void* conn, uint8_t* buf, size_t len,
                 int timeout_ms);
    int  (*write)(void* ctx, void* conn, const uint8_t* buf, size_t len,
                  int timeout_ms);
    /* Runs exactly once per successful connect, error paths included. */
    int  (*disconnect)(void* ctx, void* conn);
    void* ctx;   /* transport-wide, e.g. the stack instance */
} WolfCertTransport;

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_TYPES_H */
