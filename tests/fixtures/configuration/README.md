# Configuration fixture

`zapret-checker.xml` preserves the element order, optional sections, and root
schema-location attributes observed in the production configuration placed in
the ignored `zapret-soap-capture` directory.

All hosts, addresses, operator identifiers, credentials, key identifiers,
queue numbers, and timing values are synthetic. The fixture must not be
replaced with the production file.

The test copies this fixture into a fresh temporary directory. This lets it
verify that `timestampFile` and `customBlacklist` are resolved relative to the
selected configuration file without writing into the repository.
