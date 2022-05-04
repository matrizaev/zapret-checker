#!/usr/bin/env bash
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -L -p "12345678"
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -Ol -p "12345678"
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -Ol -p "12345678" | awk '$1 ~ /^ID:/ {print $2}' | sort | uniq | xargs -I{} sh -c "pkcs11-tool -r -p "12345678" --id "{}" --type cert --module /usr/lib/librtpkcs11ecp.so > {}.crt"

echo "Key pair ID: "
echo "6431326639343134662d636264662d646562382d353338382d613831343939366234376520" | xxd -r -p

echo
