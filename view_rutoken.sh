#!/usr/bin/env bash
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -L -p "12345678"
pkcs11-tool  --module /usr/lib/librtpkcs11ecp.so -Ol -p "12345678"
pkcs11-tool -r -p "12345678" --id "30353135343036313432303230323030323130303235353239" --type cert --module /usr/lib/librtpkcs11ecp.so > provider.crt
echo "Key pair ID: "
echo "30353135343036313432303230323030323130303235353239" | xxd -r -p

echo
