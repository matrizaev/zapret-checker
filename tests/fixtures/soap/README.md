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
