/* certs.h
 *
 * Embedded TLS test certificates for wolfIP examples
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * WARNING: These are TEST certificates only. Generate your own for production.
 *
 * To generate new certificates:
 *   openssl ecparam -genkey -name prime256v1 -out server_key.pem
 *   openssl req -new -x509 -key server_key.pem -out server_cert.pem -days 3650 \
 *       -subj "/CN=your-device/O=your-org/C=US"
 *
 * Then convert to C array:
 *   xxd -i server_cert.pem > certs.h
 *   xxd -i server_key.pem >> certs.h
 *
 * Or use the PEM strings directly as shown below.
 */

#ifndef CERTS_H
#define CERTS_H

/* ECC P-256 Server Certificate (PEM format) */
static const char server_cert_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIByTCCAW+gAwIBAgIUW3k96+M3BtW7CJRDEO/u5BaaGjgwCgYIKoZIzj0EAwIw\n"
"OjEZMBcGA1UEAwwQd29sZklQLVNUTTMySDU2MzEQMA4GA1UECgwHd29sZlNTTDEL\n"
"MAkGA1UEBhMCVVMwHhcNMjYwMTIwMTgwMjU0WhcNMzYwMTE4MTgwMjU0WjA6MRkw\n"
"FwYDVQQDDBB3b2xmSVAtU1RNMzJINTYzMRAwDgYDVQQKDAd3b2xmU1NMMQswCQYD\n"
"VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIIoRSUxD9kkXV67s06t\n"
"7yjcC7TZMIvoCwg8AJLFn/lcy9QklySeAkgWWXJrUHTM0XPYhqX9BRjF9aT4AdJ7\n"
"RTyjUzBRMB0GA1UdDgQWBBRxfBfKe/Ew5d8SArakH1z9DjxK9jAfBgNVHSMEGDAW\n"
"gBRxfBfKe/Ew5d8SArakH1z9DjxK9jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49\n"
"BAMCA0gAMEUCIEUB8ArsbYI58PGtcy9KIdR6A3z5KCQblTXZWnIE7EDUAiEA8Oyi\n"
"LwVAHQ4M2+TcVwe4LQ+xG9F6uSmu4t/psG0IT+s=\n"
"-----END CERTIFICATE-----\n";

static const int server_cert_pem_len = sizeof(server_cert_pem);

/* ECC P-256 Server Private Key (PEM format) */
static const char server_key_pem[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIJH0YKpGLqYi2CESEXZu1gS75F7XQ+rEAHPjj0u3WGmGoAoGCCqGSM49\n"
"AwEHoUQDQgAEgihFJTEP2SRdXruzTq3vKNwLtNkwi+gLCDwAksWf+VzL1CSXJJ4C\n"
"SBZZcmtQdMzRc9iGpf0FGMX1pPgB0ntFPA==\n"
"-----END EC PRIVATE KEY-----\n";

static const int server_key_pem_len = sizeof(server_key_pem);

#endif /* CERTS_H */
