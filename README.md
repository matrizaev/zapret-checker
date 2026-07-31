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

## Blacklist hash-table benchmark

Build the standalone benchmark with:

```sh
make benchmark
```

It loads an unpacked `blacklist.xml` through the production register parser and
reports load time, resident and peak memory, collision-chain statistics, and
sampled hit/miss query times for the HTTP, DNS, and IP tables. Run one bucket
configuration per process so that peak-memory measurements remain independent:

```sh
./zapret-hash-benchmark \
  --input zapret-soap-capture/blacklist.xml \
  --buckets 15013 \
  --queries 1000000
```

For example, compare several bucket counts with:

```sh
for buckets in 15013 60013 240007 960017; do
  ./zapret-hash-benchmark \
    --input zapret-soap-capture/blacklist.xml \
    --buckets "$buckets" \
    --queries 1000000
done
```

The HTTP, DNS, and IP tables can also be sized independently. A later option
overrides an earlier one. These measured sizes are also the benchmark and daemon
defaults:

```sh
./zapret-hash-benchmark \
  --input zapret-soap-capture/blacklist.xml \
  --http-buckets 60013 \
  --dns-buckets 2000003 \
  --ip-buckets 240007
```

`estimated_bytes` counts requested table, node, key, and value storage but not
allocator metadata. `post_parse_rss_kib` shows memory before glibc releases
unused heap pages, while `trimmed_rss_kib` shows the live process footprint after
`malloc_trim()`. `peak_rss_kib` also includes the parser's temporary DOM.
