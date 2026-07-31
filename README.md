# zapret-checker
Zapret-checker daemon is a set of programs and system configurations
to block blacklisted websites according to Russian law.
The blacklist is retrieved from http://vigruzki.rkn.gov.ru/
Written by Matrizaev Vyacheslav.

## Daemon configuration

By default, the daemon reads
`/etc/zapret-checker/zapret-checker.xml`. Supply another file with `--config`
(or `-c`):

```sh
./zapret-checker --config /path/to/zapret-checker.xml
```

Relative `timestampFile` and `customBlacklist` paths in the XML are resolved
relative to the directory containing the configuration file.

## Standalone SOAP downloader

`zapret-download` is a one-shot C entrypoint using the daemon's SOAP, HTTP,
base64, and XML modules. It saves the returned documents as `blacklist.xml`
and `social.xml`.

Build the daemon and downloader:

```sh
make
```

Submit an existing operator request and its detached PKCS#7 signature:

```sh
./zapret-download \
  --host vigruzki.rkn.gov.ru \
  --request-file request.xml \
  --signature-file request.xml.sign \
  --output-dir .
```

The request is sent byte-for-byte and its `requestTime` is not updated, because
changing the XML would invalidate the signature. The signature must belong to
that exact file, and the service may reject requests with an old timestamp.
Use `--poll-interval` to change the delay between `getResult` calls.

To exercise the daemon's SMTP module and send the notification with the two
ZIP archives attached:

```sh
./zapret-download \
  --host vigruzki.rkn.gov.ru \
  --request-file request.xml \
  --signature-file request.xml.sign \
  --smtp-host mail.example.net \
  --smtp-sender zapret@example.net \
  --smtp-recipient operator@example.net \
  --email-with-attachments
```

Use `--email-without-attachments` instead to send only the HTML notification.
`--smtp-recipient` may be repeated. An SMTP URL such as
`smtps://mail.example.net:465/` can be supplied when a scheme or custom port is
required.
