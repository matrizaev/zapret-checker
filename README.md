# zapret-checker
Zapret-checker daemon is a set of programs and system configurations   
to block blacklisted websites according to Russian law.  
The blacklist is retrieved from http://vigruzki.rkn.gov.ru/               
Written by Matrizaev Vyacheslav.

## Standalone SOAP downloader

`download_blacklists.py` performs the same SOAP exchange as the daemon and
saves the two returned XML documents as `blacklist.xml` and `social.xml`.
It reads the SOAP host, operator request, Rutoken PIN, and private-key ID from
the daemon's `zapret-checker.xml` configuration:

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
