#!/usr/bin/env bash
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -L -p "12345678"
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -Ol -p "12345678"
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -Ol -p "12345678" | awk '$1 ~ /^ID:/ {print $2}' | sort | uniq | xargs -I{} sh -c "pkcs11-tool -r -p "12345678" --id "{}" --type cert --module /usr/lib/librtpkcs11ecp.so > {}.crt"

echo "Key pair ID: "
echo "049c25eecc7bb12477e08e4d0522c0c8c9c96903" | xxd -r -p

echo
