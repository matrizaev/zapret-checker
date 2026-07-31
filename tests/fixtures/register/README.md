# Sanitized register fixtures

These small documents preserve the register shapes observed in the captured
`blacklist.xml` and `social.xml`. Production decisions, domains, URLs, address
ranges, organization data, and timestamps have been replaced with values from
the documentation-only `.example` and TEST-NET address ranges.

`blacklist.zip.base64` is a deterministic test archive containing the
sanitized `blacklist.xml` as `dump.xml`. It exists to exercise the same
Base64-to-ZIP-to-XML path used for downloaded register archives.

`streaming-order.xml` locks down the register's order-dependent URL behavior
and covers CDATA. `malformed.xml` and `empty-field.xml` verify that a failed
streaming parse does not commit a partial custom-blacklist overlay.
