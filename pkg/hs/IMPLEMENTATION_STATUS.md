# Tor client and onion-v3 implementation status

Checkpoint: **2026-11-08**. Results below describe the tree on which they were
produced; rerun the repository validation commands before relying on them. On
this tree, `go test ./...`, `go vet ./...`, and `go test -race ./...` pass. The
2026-11-07 certificate-fixture expiry was fixed with a reference-time test seam;
production certificate validation still uses the real clock.

Gonion is experimental. Successful interoperability tests are **not** a security
audit, proof of anonymity, censorship resistance, or complete Tor compatibility.
Persistent public guard state and guard-scoped path-bias accounting are
implemented (see below), but the new trust/guard code has not had an independent
review or audit; do not use Gonion as an anonymity boundary.

## Implemented and exercised

- **Surface traffic:** `embed.Client.DialContext` creates TCP exit streams;
  `HTTPClient` supports HTTP and HTTPS without a local SOCKS proxy. Hostnames are
  sent through Tor rather than resolved with the application's local resolver.
- **Onion client:** validates v3 addresses, derives period/blinded keys from an
  authenticated consensus, selects responsible HSDirs, fetches via final-hop
  BEGIN_DIR, validates the signed wrapper and both encryption layers, and
  authenticates the introduction and HS-ntor rendezvous. End-to-end state uses
  AES-256 and SHA3-256; C Tor's RENDEZVOUS2 compatibility padding is accepted.
- **Onion service:** `embed.Client.Listen` returns a genuine `net.Listener` over
  Tor streams, without a local listening socket or loopback backend. It establishes
  introduction circuits, publishes both overlapping descriptors, processes
  authenticated INTRODUCE2 cells, joins rendezvous points, and accepts BEGIN
  requests on the service's end-to-end hop.
- **Ownership:** the application supplies the online Ed25519 identity and reserves
  durable, strictly increasing revisions per blinded identity before publication.
  Temporary signing/introduction keys are generated in memory. Initialization
  cancellation does not terminate a successfully returned listener.
- **Lifecycle:** `Listener.Close` stops publication, introduction circuits and new
  acceptance, preserving accepted streams. `Listener.Shutdown` also terminates
  accepted streams. `Client.Close` terminates its pending work, listeners and all
  traffic circuits, including streams from listeners already closed.
- **Directory trust/cache:** pinned authority quorum, authority certificate
  signatures/cross-signatures, original signed bytes, flavor-specific download
  validation, digest-checked microdescriptors, independent snapshots and atomic
  cache replacement. A cache is never an authentication shortcut.
- **Path checks:** authenticated, currently live consensus required for selection
  and exit-pool reuse; explicit zero positional weights remain zero; Wme applies
  to Exit-only middles; directory multipliers and BadExit classification are
  honored. Selection excludes repeated identities, mutual legacy families,
  shared family IDs, IPv4 /16 and IPv6 /32 conflicts before weighted sampling.
  HS targets recover family metadata from matching consensus identities while
  retaining supplied onion keys and the original link-specifier bytes.
- **Persistent guards:** every public circuit build—exit pool and all onion
  client/service circuits—selects its fixed first hop through the caller-owned
  persistent guard manager (`pkg/path/guards.go`, `pkg/path/guards_state.go`,
  the `pkg/hs/capi` seam); persistence is caller-supplied and strictly validated,
  selection uses the vendored guard specification, and public guard choice
  fails closed instead of falling back to stateless selection. The pinned
  bridge policy is separate from this manager.
- **Streams:** bounded queues, SENDME accounting, deadlines, serialized relay
  cryptography and link-write acknowledgements. CONNECTED and DATA share a FIFO;
  a successful Write is not merely insertion into a queue that Close can discard.

## Service maintenance and bounds

Each active descriptor has three distinct introduction targets. An unavailable
target is replaced, with at most nine target attempts per descriptor and a
45-second limit per establishment. Publication uses at most four parallel uploads,
each capped at 45 seconds including circuit construction. Every responsible HSDir
is attempted; each nonempty replica group of both descriptors must acknowledge
at least one upload for initial Listen success. This means **publication**, not
proof that a particular client can reach the service.

Descriptors rotate at the authenticated consensus's SRV boundary and republish
at randomized 60–120-minute intervals or when the responsible directory set
changes. Old introduction circuits remain for three hours after their last
successful upload, including partial uploads. Maintenance now uses bounded,
randomized exponential backoff per period for failed introduction rebuilds and
partial descriptor uploads, resets on success or a material HSDir-set change,
and exposes the pending failure through `Listener.Err()` without burning a new
revision on every retry. Revision history is pruned to the two live blinded
identities; anti-rollback remains anchored to the caller's strictly increasing
`NextRevision` contract.

Local resource ceilings include 64 queued accepted connections, 32 rendezvous
circuits/builds, 16 active/retiring descriptors, 4096 replay entries per intro
key, and a bounded five-minute service-wide cookie cache. Replay history is not
evicted under a live introduction key: saturation retires that circuit/key.
These are local limits, not claims of comprehensive denial-of-service protection.

## Interoperability evidence

The opt-in tests have passed against the public Tor network with Go's race detector:

| Test | Observed result |
| --- | --- |
| `TestEmbedDialExit` | TCP to `example.com:80` and HTTPS `https://example.com/`, HTTP 200 |
| `TestEmbedDialOnion` | Tor Project's onion website, HTTP 200 |
| `TestEmbedListenOnion` | Both descriptor periods published; Gonion client exchanged and checked 1 MiB in each direction |
| Same service test, `GONION_TEST_REFERENCE_TOR=1` | Independent C Tor 0.4.8.10 client exchanged and checked 1 MiB in each direction |

The service test cancels initialization after Listen returns, closes the listener
before the independent client's accepted transfer, and checks that Client.Close
terminates accepted streams. C Tor is only an **optional test peer**, not a runtime
or build dependency of Gonion. This peer is older than the current network's
recommended protocol capabilities; newer independent peers remain important.

Default tests are offline. They include official rend-spec-v3 Appendix G.1
vectors, C Tor key-blinding/HSDir/certificate/descriptor fixtures, framing
truncations, digest rollback, malformed inputs, replay, lifecycle, publication
worker cancellation, intro-target replacement, and authenticated test-directory
fixtures. Generated round trips supplement rather than replace independent vectors.

Run from the repository root:

```sh
go test ./...
go vet ./...
go test -race ./...

GONION_NETWORK_TESTS=1 go test -race ./internal/tests -run '^TestEmbedDialExit$' -count=1 -v -timeout 5m
GONION_TEST_ONION=1 go test -race ./internal/tests -run '^TestEmbedDialOnion$' -count=1 -v -timeout 5m
GONION_TEST_SERVICE=1 GONION_TEST_REFERENCE_TOR=1 go test -race ./internal/tests -run '^TestEmbedListenOnion$' -count=1 -v -timeout 13m
```

Network tests make real relay connections and HTTP requests; the service test
publishes a temporary, freshly generated onion identity. Availability and latency
of public relays can make them fail. Leave the environment flags unset in default
CI. The reference-peer variant needs a C Tor binary on PATH.

## Remaining work, in priority order

1. **Path-bias accounting limits, and independent review of the guard batches.**
   Guard-scoped path-bias construction/usage accounting now implements the §7.3
   scaling and §7.4 rate tiers with C Tor’s strict comparisons and open-circuit
   accounting. The §7.2 END-echo usage-failure probe and `pb_dropguards=1`
   remain explicitly unsupported and fail closed. The persistent guard manager,
   its callers, and the trust/recovery batches still require independent
   specification review before any anonymity claim.
2. **Long-running resilience.** Directory refresh reconnects after its
   bootstrap/bridge channel dies (`StartConsensusRecovery`, fail-closed without a
   redial policy). Offline SRV/period rollover, changed-HSDir republish,
   delayed-client fetch, restart revision anti-rollback, bounded maintenance
   backoff, partial-publication retry and saturation tests are implemented.
   Controlled Chutney coverage of the same flows remains open.
3. **Trust-model review.** Authorization now reads privately owned authenticated
   state (`OwnAuthenticatedHydration`/`Trusted`), so mutated public clones cannot
   grant trust; the boundary still needs independent review. Cache crash and
   partial-file states now have deterministic tests, and full `ns` hydration
   remains unsupported.
4. **Coverage and audit.** Fixed modern CERTS-chain negative fixtures, broader
   parser fuzzing, sustained-throughput stream profiling and current
   C Tor/Chutney interoperability remain open. Benchmark and fuzz-smoke harnesses
   now exist, but no baseline campaign or independent security audit has been
   completed.
5. **Unsupported features.** Normal (`ns`) server-descriptor hydration,
   bridge-aware persistent guard state instances (bridge mode stays one pinned
   bridge outside the guard manager) and directory-purpose one-hop guard state,
   IPv6 exit streams, high-level client authorization,
   congestion control negotiation, proof-of-work and multi-port service routing
   are not implemented by the embedded API. The lower-level descriptor codec does
   support authorized descriptors; that does not make embed Dial authorized-service
   support complete.

Neither consensus flavor contains all relay keys by itself. Embedded bootstrap
uses authenticated **microdesc consensus plus matching microdescriptors**. See
[`../embed/README.md`](../embed/README.md) for cache names, ownership and migration.

## Sources of truth

The local `torspec` directory contains the relevant link, directory, path,
certificate and rend-spec-v3 documents, plus the vendored official guard
specification (`torspec/guard-spec`, provenance in its README). Ambiguous
behavior is checked against `tor-source`, mirror `ssh://git@git.servidordomal.lol/robogg133/tor.git`, commit
`3937194786d83725e43cdfd0b18f7d4651c2fc0e`. The source checkout is a reference only:
no C code, native wrapper, CGO or external Tor daemon is linked into the client.
