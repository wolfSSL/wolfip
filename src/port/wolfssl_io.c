#include "wolfip.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

static struct wolfIP *ref_ipstack = NULL; 

static int wolfIP_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret = 0;
    int fd = (intptr_t)ctx;
    (void)ssl;
    if (!ref_ipstack)
        return -1;
    ret = wolfIP_sock_recv(ref_ipstack, fd, buf, sz, 0);
    if (ret == -11)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    else if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

static int wolfIP_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret = 0;
    int fd = (intptr_t)ctx;
    (void)ssl;
    if (!ref_ipstack)
        return -1;
    ret = wolfIP_sock_send(ref_ipstack, fd, buf, sz, 0);
    if (ret == -11)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    else if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

int wolfSSL_SetIO_FT_CTX(WOLFSSL_CTX* ctx, struct wolfIP *s)
{
    wolfSSL_SetIORecv(ctx, wolfIP_io_recv);
    wolfSSL_SetIOSend(ctx, wolfIP_io_send);
    ref_ipstack = s;
    return 0;
}

int wolfSSL_SetIO_FT(WOLFSSL* ssl, int fd)
{
    wolfSSL_SetIOReadCtx(ssl, (void*)(intptr_t)fd);
    wolfSSL_SetIOWriteCtx(ssl, (void*)(intptr_t)fd);
    return 0;
}

