# Authority certificate fixtures

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
