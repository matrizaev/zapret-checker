# Sanitized SOAP fixtures

These fixtures preserve the XML element names and response variants observed
in a production `zapret-download` capture. All dates, request codes, operator
details, comments, and archive payloads have been replaced with synthetic test
values.

The observed sequence was:

1. one `getLastDumpDateExResponse`;
2. one successful `sendRequestResponse`;
3. fourteen pending `getResultResponse` messages;
4. one completed `getResultResponse` containing the blacklist archive; and
5. one `getResultResponse` containing the social-resources archive, despite
   being requested with `getResultSocResources`.

The raw production capture is intentionally ignored by Git and must never be
used as a committed test fixture.

`operator-request.xml` preserves only the captured request's field layout and
uses synthetic identity data. The production PKCS#7 signature is not copied:
the prepared-request path treats it as opaque bytes, and retaining a live
signature would add sensitive material without improving parser coverage.

The contract fixtures ending in `minimal-response`, `rejected-response`, and
`error-response` are derived from the public OperatorRequest WSDL and operator
guide version 4.13 (2024-08-12). They cover optional `sendRequestResponse`
fields and the documented terminal negative `getResult` codes without copying
operator data or credentials from the ignored capture directory.
