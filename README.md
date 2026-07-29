# zapret-checker
Zapret-checker daemon is a set of programs and system configurations   
to block blacklisted websites according to Russian law.  
The blacklist is retrieved from http://vigruzki.rkn.gov.ru/               
Written by Matrizaev Vyacheslav.

## Standalone SOAP downloader

`download_blacklists.py` performs the same SOAP exchange as the daemon and
saves the two returned XML documents as `blacklist.xml` and `social.xml`.

To submit an existing request and its detached PKCS#7 signature without a
configuration file or connected Rutoken:

```sh
python3 download_blacklists.py \
  --host vigruzki.rkn.gov.ru \
  --request-file request.xml \
  --signature-file request.xml.sign \
  --output-dir .
```

The request is sent byte-for-byte and its `requestTime` is not updated, because
changing the XML would invalidate the signature. The signature must belong to
that exact file, and the service may reject requests with an old timestamp.

Alternatively, the script can create and sign a fresh request using the SOAP
host, operator request, Rutoken PIN, and private-key ID from the daemon's
`zapret-checker.xml` configuration:

```sh
python3 download_blacklists.py \
  --config /etc/zapret-checker/zapret-checker.xml \
  --signer ./rutoken-sign \
  --output-dir .
```

The `rutoken-sign` executable must be built and a matching Rutoken must be
connected. Use `--pin` or `--key-id` to override the corresponding config
values, and `--slot` when the token is not in slot zero. Run
`python3 download_blacklists.py --help` for all polling and timeout options.
