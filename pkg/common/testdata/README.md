# Directory cryptography fixtures

## Bridge server descriptors

`bridge-0.desc` and `bridge-1.desc` are the first two signed server descriptors
in C Tor's `src/test/test_descriptors.inc`, commit
`3937194786d83725e43cdfd0b18f7d4651c2fc0e` (lines 4–56 and 59–111).
Only C string escaping and the unsigned `@uploaded-at`/`@source` annotations
were removed. No signed byte, timestamp, key or signature was regenerated.
These public local-network fixtures exercise both ntor cross-certificate sign
bits, identity certificates, TAP cross-certificates and RSA/Ed25519 signatures.
They are validated at 2020-10-13 14:00 UTC, not with the production clock.

SHA-256:

- `bridge-0.desc`: `24f1046bcfce4a65855baef00aa88f350af7a74bb1d45d68b3b1551eedeb40d6`
- `bridge-1.desc`: `372129fee7e91fca29a6e092c565c502531331b56f1b4ef5afc93c639685cee0`

## Authority certificates

`authority-cert-b.pem`, `authority-cert-c.pem`, `authority-signkey-b.pem` and
`authority-signkey-c.pem` come from the published test constants in C Tor's
`src/test/test_data.c`, commit `3937194786d83725e43cdfd0b18f7d4651c2fc0e`.

These are **public test-only signing keys**, not production directory authority
secrets. Tests validate the original authority certifications and cross-signatures
at the fixture's 2014 validity time, then sign small test consensuses with these
keys. The tests explicitly pin the fixture identities and verify that Gonion's
public authority list does not accept them. No production verification path is
replaced or relaxed.

Source: Tor Project, https://gitlab.torproject.org/tpo/core/tor
Local reference mirror: `ssh://git@git.servidordomal.lol/robogg133/tor.git`.

The fixtures are distributed under the Tor Project's BSD-3-Clause license; see
[`../../hs/desc/testdata/TOR-LICENSE`](../../hs/desc/testdata/TOR-LICENSE).
