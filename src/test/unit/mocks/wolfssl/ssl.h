/* Mock wolfssl/ssl.h for unit tests.
 * Only includes pieces needed by src/port/wolfssl_io.c tests.
 */
#ifndef WOLFSSL_SSL_H
#define WOLFSSL_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WOLFSSL_CTX {
    int id;
} WOLFSSL_CTX;

typedef struct WOLFSSL {
    WOLFSSL_CTX *ctx;
    void *rctx;
    void *wctx;
} WOLFSSL;

typedef int (*CallbackIORecv)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(WOLFSSL *ssl, char *buf, int sz, void *ctx);

#define WOLFSSL_CBIO_ERR_GENERAL    (-1)
#define WOLFSSL_CBIO_ERR_WANT_READ  (-2)
#define WOLFSSL_CBIO_ERR_WANT_WRITE (-2)
#define WOLFSSL_CBIO_ERR_CONN_CLOSE (-5)

int wolfSSL_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv cb);
int wolfSSL_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend cb);
int wolfSSL_SetIOReadCtx(WOLFSSL *ssl, void *ctx);
int wolfSSL_SetIOWriteCtx(WOLFSSL *ssl, void *ctx);
WOLFSSL_CTX *wolfSSL_get_SSL_CTX(WOLFSSL *ssl);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SSL_H */
