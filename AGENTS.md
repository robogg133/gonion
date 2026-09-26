# AGENTS.md

## Project

Gonion is an experimental pure-Go implementation of a Tor client and onion-v3
service. It covers OR/TLS channels, cells, circuits, streams, directories, path
selection, transports, and embedded Dial/Listen APIs. It must not be treated as
production-ready or capable of providing real anonymity without a security and
interoperability review.

## Read First And Resume

Before continuing implementation, read:

1. `docs/CONTEXT.md`: original goals, accepted decisions, architecture, and work
   already completed. Do not restart completed protocol work from obsolete notes.
2. `docs/STATUS.md`: latest validation, known failures, and remaining limitations.
3. `docs/NEXT_STEPS.md`: immediate resume sequence and completion criteria.
4. `pkg/embed/README.md`: public ownership, lifecycle, networking, and cache contracts.

These documents are a dated checkpoint, not a substitute for inspecting current
code, `git status`, and the applicable specifications. Update status and validation
records when behavior or test results change. Never turn a historical pass into a
claim that the current tree is fully validated.

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
- The user-requested mirror is `ssh://git@git.servidordomal.lol/robogg133/tor.git`.
  A reference checkout already exists at `tor-source`; the recorded reference
  commit is `3937194786d83725e43cdfd0b18f7d4651c2fc0e`. Inspect it before fetching
  another copy. Do not modify or commit the reference tree as implementation code.
- If the applicable specification is absent locally, obtain the authoritative
  document before implementation. In particular, persistent guard selection
  needs the guard specification as well as `path-spec`, not an invented shortcut.

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

## Accepted Embedding And Service Contracts

- `DefaultOptions()` chooses local defaults only. Network, storage, identity and
  durable revision policy belong to the caller; do not add hidden disk writes.
- Bootstrap and traffic networking are separate. `ORDialer` opens bootstrap only;
  `GuardDialer` must connect to the selected traffic guard. No silent direct TCP
  fallback or substitution of an unrelated bridge is permitted.
- Match bootstrap CERTS against an explicit expected RSA identity, supplied by
  `BootstrapIdentity` or connection metadata. A transport certificate alone is
  not a replacement for the Tor relay identity check.
- `Listen` returns a genuine `net.Listener` over Tor streams. Do not bind a local
  listening socket or forward accepted streams to a loopback backend.
- The caller supplies the online Ed25519 identity. Temporary introduction and
  descriptor-signing keys stay in memory. Reserve and durably persist a strictly
  increasing revision per blinded identity before attempting publication.
- Listen readiness means introduction establishment and acknowledged descriptor
  publication, not proof of reachability. Its initialization context must not own
  the returned listener's lifetime.
- `Listener.Close()` stops new acceptance/publication while preserving accepted
  connections. `Listener.Shutdown()` and `Client.Close()` terminate them. Client
  ownership also covers connections whose listener has already been closed.
- Preserve source compatibility where safe. Document security-required breaking
  changes rather than retaining an insecure fallback.
- Keep `cached-consensus` (signed ns text), `cached-microdesc-consensus` (signed
  microdesc text), and `gonion-consensus.json` (hydrated cache) distinct. Neither
  consensus alone supplies all relay keys, and cached models are not trust proof.

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
- Public-network tests and temporary onion publication were authorized for this
  ongoing implementation task. Keep them explicitly opt-in; do not repeatedly
  ask for the same authorization or enable them in the default test suite.
- C Tor may be used as an opt-in independent test peer, never as the Go client's
  runtime or build dependency. Record its version and the exact tested flows.
- An expected fixture value must not be changed merely to make a test pass.
  Establish fixture provenance and isolate parser behavior first.
- Respect editor/private-file access restrictions, including test PEM files.
  Do not bypass a denied read using another tool. Published test-key provenance
  is documented in `pkg/common/testdata/README.md`; the existing tests can be run
  without exposing those files' contents.
- Do not commit or create branches unless the user asks. The worktree contains
  substantial uncommitted and untracked work; a small `git diff --stat` is not a
  complete inventory of new files.
