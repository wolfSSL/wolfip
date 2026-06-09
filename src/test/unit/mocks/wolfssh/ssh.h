/* Mock wolfssh/ssh.h for unit tests.
 * Only includes pieces needed by src/port/wolfssh_io.c tests.
 */
#ifndef WOLFSSH_SSH_H
#define WOLFSSH_SSH_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int word32;

typedef struct WOLFSSH_CTX {
    int id;
} WOLFSSH_CTX;

typedef struct WOLFSSH {
    WOLFSSH_CTX *ctx;
    void *rctx;
    void *wctx;
} WOLFSSH;

typedef int (*WS_CallbackIORecv)(WOLFSSH *ssh, void *buf, word32 sz, void *ctx);
typedef int (*WS_CallbackIOSend)(WOLFSSH *ssh, void *buf, word32 sz, void *ctx);

/* Return codes (subset, matching real wolfSSH values). */
#define WS_SUCCESS       (0)
#define WS_BAD_ARGUMENT  (-2)
#define WS_MEMORY_E      (-6)

/* Custom IO callback error codes (subset, matching real wolfSSH values). */
#define WS_CBIO_ERR_GENERAL    (-1)
#define WS_CBIO_ERR_WANT_READ  (-2)
#define WS_CBIO_ERR_WANT_WRITE (-3)
#define WS_CBIO_ERR_CONN_CLOSE (-6)

void wolfSSH_SetIORecv(WOLFSSH_CTX *ctx, WS_CallbackIORecv cb);
void wolfSSH_SetIOSend(WOLFSSH_CTX *ctx, WS_CallbackIOSend cb);
void wolfSSH_SetIOReadCtx(WOLFSSH *ssh, void *ctx);
void wolfSSH_SetIOWriteCtx(WOLFSSH *ssh, void *ctx);
void *wolfSSH_GetIOReadCtx(WOLFSSH *ssh);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SSH_H */
