# Tor descriptor fixtures

`tor-bad-signature.desc` is the decoded C string `HS_DESC_BAD_SIG` from
`tor-source/src/test/test_hs_descriptor.inc`, unchanged. It is a negative
signature-line fixture (a forbidden leading space, Tor issue #23233); the
signature itself and its type-08 signing certificate are valid at Unix time
1502661599, the validation time used in Tor's `test_decode_bad_signature`.

The tests also transcribe these Tor unit vectors with source comments:

- `src/test/test_hs_common.c`, `test_blinding_basics`: expanded identity and
  blinded private/public keys, period 1234, period length 1440 minutes,
  subcredential.
- `src/test/test_hs_descriptor.c`, `test_build_authorized_client`: X25519
  ephemeral private key, client public key, descriptor cookie, IV, client ID,
  encrypted cookie.
- `src/test/test_hs_descriptor.c`, `test_decode_invalid_intro_point`: individual
  type-09 and type-0B certificates. These are independently signed fixtures,
  not a complete mutually consistent introduction point.

Tor source: https://gitlab.torproject.org/tpo/core/tor
The Tor source and these fixtures are distributed under Tor's BSD license;
see the included `TOR-LICENSE` (the applicable portion of `tor-source/LICENSE`).

Generated Go round trips and mutation tests supplement the Tor fixtures. They
are not captured interoperability tests and do not establish network anonymity
or complete Tor interoperability.
