#!/usr/bin/env python3
# gen_certs.py -- generate the TLS test PKI for the STM32C5A3ZG wolfIP TLS client.
#
# Copyright (C) 2026 wolfSSL Inc.
#
# The CA and server EC keys are fixed scalars and the client key is the NIST
# P-256 CAVP SigGen vector from identity_key.h. ECDSA cert DER is not byte-
# reproducible (random nonce), so re-running this script produces a fresh but
# internally-matched PKI: rebuild + reflash the firmware after regenerating.
#
# Outputs:
#   tls_certs.h   (committed) -- client cert + client key (public CAVP scalar) +
#                 CA cert, embedded into the firmware. All public material.
#   tls-certs/    (git-ignored) -- ca.pem, server.pem, server.key.pem for the
#                 test server (server.key.pem is a throwaway TEST key, hence not
#                 committed), plus client.pem/client.key.pem for reference.
#
# Test server the device connects to (see README.md):
#   openssl s_server -accept 11111 -tls1_3 -cert server.pem -key server.key.pem \
#       -Verify 1 -CAfile ca.pem -www
#
# Usage:  cd src/port/stm32c5a3 && python3 gen_certs.py
# Requires: python3-cryptography.  TEST ONLY -- never use for production.

import os
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "tls-certs")
os.makedirs(OUT, exist_ok=True)

# Client identity keypair = NIST P-256 CAVP SigGen vector (identity_key.h).
# The scalar is public (a published KAT vector); it is the identity key whose
# private form the device holds only in DHUK-wrapped shape at runtime.
D  = bytes.fromhex("708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590")
QX = bytes.fromhex("29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab")
QY = bytes.fromhex("08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800")

# CA and server use P-256 keys from fixed scalars (< the P-256 order n; the
# high 0x0f byte keeps them in range). ECDSA is used throughout so the device's
# wolfSSL (no Ed25519) can parse the server certificate it receives. TEST-ONLY
# throwaway keys. NOTE: ECDSA signing uses a random nonce, so the cert DER is
# NOT byte-reproducible across runs -- this is why the whole matched PKI (this
# header AND the tls-certs/ host material) is committed together rather than
# regenerated on demand; regenerating replaces the entire set at once.
CA_D     = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
SERVER_D = 0x0e0d0c0b0a09080706050403020100ff0e0d0c0b0a09080706050403020100ff

client_key = ec.derive_private_key(int.from_bytes(D, "big"), ec.SECP256R1())
pub = client_key.public_key().public_numbers()
assert pub.x == int.from_bytes(QX, "big") and pub.y == int.from_bytes(QY, "big"), \
    "derived public key does not match identity_key_qx/qy in identity_key.h"
print("client identity pubkey matches identity_key_qx/qy: OK")

ca_key = ec.derive_private_key(CA_D, ec.SECP256R1())
server_key = ec.derive_private_key(SERVER_D, ec.SECP256R1())


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "wolfSSL Test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


# Fixed validity window so the certs (and thus the DER bytes) are deterministic.
t0 = datetime.datetime(2026, 1, 1)
t1 = datetime.datetime(2036, 1, 1)

ca = (x509.CertificateBuilder()
      .subject_name(name("wolfIP Test CA")).issuer_name(name("wolfIP Test CA"))
      .public_key(ca_key.public_key()).serial_number(1)
      .not_valid_before(t0).not_valid_after(t1)
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
      .sign(ca_key, hashes.SHA256()))

client_cert = (x509.CertificateBuilder()
      .subject_name(name("stm32c5a3-client")).issuer_name(ca.subject)
      .public_key(client_key.public_key()).serial_number(2)
      .not_valid_before(t0).not_valid_after(t1)
      .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
      .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False)
      .sign(ca_key, hashes.SHA256()))

server_cert = (x509.CertificateBuilder()
      .subject_name(name("stm32c5a3-server")).issuer_name(ca.subject)
      .public_key(server_key.public_key()).serial_number(3)
      .not_valid_before(t0).not_valid_after(t1)
      .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
      .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
      .sign(ca_key, hashes.SHA256()))

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
NOENC = serialization.NoEncryption()
SEC1 = serialization.PrivateFormat.TraditionalOpenSSL   # P-256 client/server keys


def w(fn, data):
    with open(os.path.join(OUT, fn), "wb") as f:
        f.write(data)


w("ca.pem", ca.public_bytes(PEM))
w("client.pem", client_cert.public_bytes(PEM))
w("client.key.pem", client_key.private_bytes(PEM, SEC1, NOENC))
w("server.pem", server_cert.public_bytes(PEM))
w("server.key.pem", server_key.private_bytes(PEM, SEC1, NOENC))

client_der = client_cert.public_bytes(DER)
client_key_der = client_key.private_bytes(DER, SEC1, NOENC)
ca_der = ca.public_bytes(DER)


def carr(nm, b):
    out = ["static const unsigned char %s[] = {" % nm]
    for i in range(0, len(b), 12):
        out.append("    " + "".join("0x%02x, " % c for c in b[i:i + 12]).rstrip())
    out.append("};")
    out.append("static const unsigned int %s_len = %d;" % (nm, len(b)))
    return "\n".join(out)


hdr = """/* tls_certs.h -- GENERATED by gen_certs.py; do not edit by hand.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * TLS 1.3 mutual-auth test PKI for the STM32C5A3ZG wolfIP client. TEST ONLY.
 *
 * Provenance / regeneration:
 *   cd src/port/stm32c5a3 && python3 gen_certs.py
 * Fixed CA/server scalars; client key is the NIST P-256 CAVP SigGen vector from
 * identity_key.h. The host material (tls-certs/, git-ignored -- it holds a
 * throwaway test key) is regenerated on demand. ECDSA cert DER is not byte-
 * reproducible, so regenerating also rewrites this header: rebuild + reflash
 * after regenerating. The host material feeds:
 *     openssl s_server -accept 11111 -tls1_3 -cert server.pem \\
 *         -key server.key.pem -Verify 1 -CAfile ca.pem -www
 *
 * Contents below (all public material -- no live secret):
 *   client_cert_der  -- the device client certificate (binds the P-256
 *                       identity public key identity_key_qx/qy).
 *   client_key_der   -- SEC1 EC private key = the RAW identity scalar, used
 *                       only by the software bring-up build (ENABLE_TLS_CLIENT
 *                       without ENABLE_DHUK_KEY). The DHUK build signs through
 *                       the crypto callback and never touches this.
 *   ca_cert_der      -- the test CA (to verify the server, if enabled).
 */
#ifndef TLS_CERTS_H
#define TLS_CERTS_H

%s

%s

%s

#endif /* TLS_CERTS_H */
""" % (carr("client_cert_der", client_der),
       carr("client_key_der", client_key_der),
       carr("ca_cert_der", ca_der))

with open(os.path.join(HERE, "tls_certs.h"), "w") as f:
    f.write(hdr)

print("wrote tls_certs.h and", sorted(os.listdir(OUT)))
print("client_der=%d client_key_der=%d ca_der=%d bytes" %
      (len(client_der), len(client_key_der), len(ca_der)))
