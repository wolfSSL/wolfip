#!/bin/sh
#
OUT_DIR=${1:-build/certs}
OUT_DIR_CVAR=$(echo $OUT_DIR | sed -e 's/\//_/g')

echo ${OUT_DIR_CVAR}

: "${COUNTRY:=US}"
: "${STATE:=State}"
: "${CITY:=City}"
: "${ORG:=ExampleOrg}"
: "${ORG_UNIT:=IT}"
: "${CA_COMMON_NAME:=Example CA}"
: "${SERVER_COMMON_NAME:=example.com}"
: "${DAYS_CA:=3650}"           # CA certificate validity in days (10 years)
: "${DAYS_SERVER:=825}"        # Server certificate validity in days (2 years)
: "${ECC_CURVE:=secp384r1}"    # ECC curve to use

# Create the output directory if it doesn't exist
mkdir -p "$OUT_DIR"

# 1. Generate CA private key
openssl ecparam -name "$ECC_CURVE" -genkey -noout -out "$OUT_DIR/ca.key"

# 2. Generate the CA self-signed certificate (PEM format)
openssl req -x509 -new -key "$OUT_DIR/ca.key" -sha256 -days "$DAYS_CA" -out "$OUT_DIR/ca.crt" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$ORG_UNIT/CN=$CA_COMMON_NAME"

# 3. Convert CA certificate to DER format
openssl x509 -in "$OUT_DIR/ca.crt" -outform DER -out "$OUT_DIR/ca.der"

xxd -i "$OUT_DIR/ca.der" |sed -e "s/unsigned/const unsigned/g" | sed -e "s/${OUT_DIR_CVAR}_//g"  > "$OUT_DIR/ca_cert.c"


echo "==== Generating server private key ===="

# 4. Generate server private key
openssl ecparam -name "$ECC_CURVE" -genkey -noout -out "$OUT_DIR/server.key"

# 5. Convert server private key to DER format
openssl pkcs8 -topk8 -nocrypt -in "$OUT_DIR/server.key" -outform DER -out "$OUT_DIR/server.key.der"

xxd -i "$OUT_DIR/server.key.der" |sed -e "s/unsigned/const unsigned/g" | sed -e "s/${OUT_DIR_CVAR}_//g" > "$OUT_DIR/server_key.c"


echo "==== Generating server Certificate Signing Request (CSR) ===="

# 6. Generate server Certificate Signing Request (CSR)
openssl req -new -key "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$ORG_UNIT/CN=$SERVER_COMMON_NAME"

echo "==== Signing server certificate with the CA ===="

# 7. Sign the server CSR with the CA to create a server certificate (PEM format)
openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
    -CAcreateserial -out "$OUT_DIR/server.crt" -days "$DAYS_SERVER" -sha256

# 8. Convert server certificate to DER format
openssl x509 -in "$OUT_DIR/server.crt" -outform DER -out "$OUT_DIR/server.der"

xxd -i "$OUT_DIR/server.der" |sed -e "s/unsigned/const unsigned/g" | sed -e "s/${OUT_DIR_CVAR}_//g" > "$OUT_DIR/server_cert.c"

echo "==== Done ===="
