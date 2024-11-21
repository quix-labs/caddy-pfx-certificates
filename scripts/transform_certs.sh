#!/usr/bin/env bash

IN=./path/to/your.pfx
PASS=pfx_password
OUT_PATH=./your_output

mkdir -p $OUT_PATH

function openssl-pass {
  openssl pkcs12 -in "$IN" -password "pass:$PASS" "$@"
}

# Extract the RSA Key from the PFX file:
openssl-pass -nocerts -nodes -out "$OUT_PATH/rsa-key-pfx.pem"

# Extract the Public Certificate from the PFX file:
openssl-pass -clcerts -nokeys -out "$OUT_PATH/public-cert-pfx.pem"

# Extract the CA Chain from the PFX file:
openssl-pass -cacerts -nokeys -chain -out "$OUT_PATH/ca-pfx.pem"

# Convert the RSA Key from PFX format to PEM:
openssl rsa -in $OUT_PATH/rsa-key-pfx.pem -out "$OUT_PATH/rsa-key.pem"

# Convert the x509 Public Certificate and CA Chain from PFX to PEM format:
openssl x509 -in "$OUT_PATH/public-cert-pfx.pem" -out "$OUT_PATH/cert.pem"
openssl x509 -in "$OUT_PATH/ca-pfx.pem" -out "$OUT_PATH/ca.pem"

# Combine certs to generate chain
cat "$OUT_PATH/cert.pem" "$OUT_PATH/ca.pem" > "$OUT_PATH/chain.pem"

# Remove unused/unnecessary files
rm "$OUT_PATH/ca-pfx.pem" "$OUT_PATH/public-cert-pfx.pem" "$OUT_PATH/rsa-key-pfx.pem"

# Run openssl to verify certificate
openssl verify -CAfile "$OUT_PATH/chain.pem" "$OUT_PATH/ca.pem"