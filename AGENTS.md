# AGENTS.md

## Project

Gonion is an pure-Go implementation of a Tor client. It covers
OR/TLS channels, cells, circuits, streams, directories, path selection,
transports, and an onion service v3 client. It must not be treated as
production-ready or capable of providing real anonymity without a security and
interoperability review.

## Language And Dependencies

- English is mandatory for source comments, documentation, commit messages, and
  user-facing errors added to this repository.
- The client implementation must remain pure Go: do not add CGO, C libraries,
  C bindings, native wrappers, or an external Tor daemon dependency.
- Scripts have no prescribed implementation language. Choose a language only
  when adding or changing a script, and document any nonstandard runtime need.

## Source Of Truth

- For every protocol detail, read the applicable `torspec` section before
  editing. Do not rely on memory, blogs, or inferred constants.
- Confirm ambiguous behavior against the C Tor implementation in `tor-source`.

## Security Rules

- Never accept a consensus, relay, certificate, key, onion address, length, or
  protocol field without explicit validation.
- Never replace cryptographic verification with `InsecureSkipVerify`, test data,
  zero values, or a best-effort path. Channel TLS may ignore Web PKI only because
  relay identity is authenticated by `CERTS` and matched against the expected
  consensus or fallback identity.
- When changing network parsers, bound lengths, validate bounds before indexing
  slices, and return errors. Remote input must not panic, allocate without
  bounds, or desynchronize framing.
- Preserve `crypto/rand` for protocol values. Do not use `math/rand` for a
  secret, key, nonce, cookie, or security-relevant identifier.
- Do not claim anonymity, censorship resistance, or Tor compatibility without
  the corresponding interoperability test.

## Protocol

- Frame cells by command and negotiated version: `VERSIONS` and commands >= 128
  are variable length; all other cells are fixed length. Never assume that every
  cell has a 509-byte body.
- Negotiate the highest common Link version and honor `pr` subprotocol
  capabilities before using optional features.
- Preserve `CircID`, `StreamID`, direction, and `RELAY_EARLY` rules. `EXTEND2`
  must use `RELAY_EARLY`; a control cell uses StreamID zero.
- Keep cryptographic state per hop. Update a digest only when a cell is
  recognized, and use the algorithm and key size required for that circuit type.
  HS-ntor uses AES-256 and SHA3-256, not ordinary circuit values.
- Validate consensus signatures and quorum before using routers, weights, SRV,
  or microdescriptors. Never select paths from an unauthenticated consensus.
- Path selection must follow `path-spec`: persistent guards, consensus weights,
  families, network diversity, flags, and port policies.

## Onion Services V3

- Read all relevant `rend-spec` sections before changing `pkg/hs`.
- Validate a v3 address: length, base32 encoding, SHA3-256 checksum, version 3,
  and absence of an Ed25519 torsion component.
- Use consensus `valid-after`, a period in minutes, and the exact field ordering
  in key blinding, HSDir, and descriptor ID hashes.
- A client does not send `ESTABLISH_INTRO`; it sends `INTRODUCE1` as a control
  cell to the introduction point. Its payload must include every required field,
  including rendezvous point link specifiers and the specified onion key.
- Parse and validate the signed outer wrapper, both encryption layers, and intro
  point certificates and keys before beginning rendezvous.

## Changes And Tests

- Read every caller before fixing a protocol function. Fix the shared root cause,
  not only the path that exposed it.
- Prefer the smallest correct change. Do not add dependencies, abstractions, or
  speculative compatibility.
- Every framing, parser, cryptography, state, or selection change must include a
  small test using an official torspec vector or a validated captured fixture.
- When Go is available, run `go test ./...`, `go vet ./...`, and
  `go test -race ./...`. Network tests must be opt-in and must not depend on a
  public relay in the default suite.
- Do not alter or revert another contributor's local changes. Inspect
  `git status` before editing and limit the diff to required files.
