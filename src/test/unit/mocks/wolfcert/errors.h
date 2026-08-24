/* Mock wolfcert/errors.h for unit tests.
 * Only the codes src/port/wolfcert_io.c uses; values match wolfCert's.
 */
#ifndef WOLFCERT_ERRORS_H
#define WOLFCERT_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WOLFCERT_OK              =   0,
    WOLFCERT_ERR_GENERIC     =  -1,
    WOLFCERT_ERR_BAD_ARG     =  -2,
    WOLFCERT_ERR_MEMORY      =  -3,
    WOLFCERT_ERR_IO          =  -4,
    WOLFCERT_ERR_NOT_FOUND   = -11,
    WOLFCERT_ERR_WANT_READ   = -14,
    WOLFCERT_ERR_WANT_WRITE  = -15,
    WOLFCERT_ERR_CONN_CLOSED = -16
};

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_ERRORS_H */
