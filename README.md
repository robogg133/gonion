# Gonion

![Gonion](icon.png)

An experimental **pure-Go Tor client and onion-v3 service** designed for embedding.
No CGO, native bindings, `libtor`, external Tor daemon or local SOCKS proxy is
required by the client implementation.

> **Not production-ready or an anonymity boundary.** Persistent public guard
> state is required for every circuit and path-bias accounting is implemented,
> but the guard/trust/path-bias code is new and awaiting independent review,
> and no full security audit has been completed. Successful TCP/HTTPS/onion
> interoperability tests do not establish anonymity, censorship resistance,
> reduced detectability, or complete Tor compatibility.

## Supported scope

Production-oriented use must stay inside this scope; anything outside fails
closed and requires separate specification review and acceptance evidence:

- Surface TCP/IPv4 Dial and onion-v3 Dial/Listen, over direct networking or one
  caller-pinned bridge. `Options.Guards` (persistent, caller-owned public guard
  state) is mandatory outside bridge mode.
- Deliberately unsupported and rejected: IPv6 exit streams, multi-bridge
  selection, authorized onion services, congestion-control/PoW negotiation,
  multi-port service routing, and full `ns` server-descriptor hydration.
- Known path-bias limits: §7.3 scaling and §7.4 rate tiers are implemented; the
  §7.2 END-echo probe and `pb_dropguards=1` remain explicitly unsupported and
  fail closed.
- Vulnerability disclosure: [SECURITY.md](SECURITY.md).

## Current functionality

- TLS/OR link negotiation, relay CERTS authentication and expected identity pins.
- Tor cell framing, ntor circuit construction, per-hop cryptography, streams,
  SENDME flow control and deadlines. Circuit ownership now has one idempotent
  teardown path, random collision-checked IDs, context/deadline-aware build and
  stream APIs, and per-connection circuit/stream/queue ceilings.
- Authenticated consensus download, microdescriptor hydration, refresh,
  connection-owned refresh recovery after channel loss, crash-consistent atomic
  cache replacement, and separate raw/hydrated cache files. The Tor cache backend
  requires an explicit caller-owned directory.
- `pkg/embed`: `DefaultOptions`, caller-controlled bootstrap/guard dialers and
  storage, persistent caller-owned public guard state (`Options.Guards`, one
  guard choice shared across exit and onion circuit construction; construction
  fails closed without it), TCP/HTTPS/onion Dial, circuit pooling and lifecycle
  management. A privacy-safe optional log writer and `Stats` snapshot expose
  bootstrap, guard, bridge and listener failure classes without destination
  labels.
- Onion-v3 descriptor validation, introduction/rendezvous, service publication,
  deterministic SRV/period rollover, bounded maintenance backoff and restart
  revision anti-rollback.
- A Tor-backed `net.Listener` for onion services, without a local listening socket.
  Service identities and durable descriptor revision allocation belong to callers.
- Transport adapters for meek, webtunnel, Snowflake and obfs4. Meek and webtunnel
  honor context cancellation; obfs4 requires a pinned RSA identity and has local
  server-handshake evidence. Public end-to-end obfs4 bootstrap is still blocked by
  the root connection deadline API.

See the [embedding guide](pkg/embed/README.md),
[runnable examples](examples/embed/README.md), and
[detailed implementation status and remaining work](pkg/hs/IMPLEMENTATION_STATUS.md).

The published tree documents current behavior through this file, `SECURITY.md`,
`pkg/embed/README.md`, and `pkg/hs/IMPLEMENTATION_STATUS.md`. Historical results
belong only to the trees on which they were produced; rerun the current
validation commands before relying on them.

## Architecture

| Area | Responsibility |
| --- | --- |
| Root `conn*.go` | OR/TLS handshake, relay authentication, cell I/O and connection lifetime |
| Root `circuit*.go` | Circuit construction, relay encryption/control, routing and service-side acceptance |
| Root `stream*.go` | Tor-backed `net.Conn`, buffering, deadlines, flow control and close behavior |
| `pkg/cells`, `pkg/lspec` | Bounded wire encoding/decoding for link/relay cells and link specifiers |
| `pkg/crypto`, `internal/hops`, `internal/window` | Ordinary circuit crypto, per-hop state and flow-control accounting |
| `pkg/common`, `pkg/parsers` | Directory models, consensus signature/quorum verification, text/JSON/microdescriptor parsing |
| Root `bootstraping.go`, `helpers.go` | Directory download, hash-checked hydration and consensus refresh |
| `pkg/storage` | Caller-selected in-memory or on-disk public directory caches |
| `pkg/path` | Weighted relay selection, family/identity/subnet constraints, persistent public-default guard manager (`pkg/path/guards.go`) |
| `pkg/hs/onion`, `pkg/hs/crypto`, `pkg/hs/desc` | Onion address checks, key blinding, HS-ntor, signed/encrypted descriptors |
| `pkg/hs`, `pkg/hs/capi` | Client/service orchestration and integration with real circuits |
| `pkg/embed` | Application-facing Dial/HTTP/Listen APIs and resource ownership |
| `pkg/transports` | Transport adapters, independent of application network policy |
| `internal/tests` | Opt-in public-network interoperability tests |
| `torspec`, `tor-source` | Local protocol and C Tor references; not runtime dependencies |

The implementation keeps ordinary circuit state separate from HS end-to-end
AES-256/SHA3-256 state. Descriptor fetching/publication uses directory streams on
dedicated circuits. A service's accepted stream is delivered directly to the
application rather than forwarded to a local TCP server.

## Consensus formats

The normal `ns` consensus and microdesc consensus are distinct signed formats.
**Neither contains every relay key by itself.** Embedded bootstrap uses the
microdesc consensus plus matching microdescriptors.

- `cached-consensus`: original signed `ns` text.
- `cached-microdesc-consensus`: original signed microdesc text.
- `gonion-consensus.json`: hydrated Gonion snapshot with original signed and
  descriptor bytes, reverified before use.

See the [cache and ownership contract](pkg/embed/README.md#consensus-cache-and-download-flavors).

## Validation

```sh
go test ./...
go vet ./...
go test -race ./...
```

The default suite is offline. Opt-in tests have exercised public exit TCP/HTTPS,
the Tor Project's onion website, and Gonion service publication with both a
Gonion client and an independent C Tor client. The service test checks 1 MiB in
each direction and listener/client close semantics. Commands, dependencies and
limits are documented in the [status report](pkg/hs/IMPLEMENTATION_STATUS.md).

Public-network tests are not availability guarantees. They do not replace fixed
protocol vectors, negative tests, fuzzing, controlled-network testing or audit.

## Development priorities

1. Review the implemented persistent guard state/persistence and the integrated
   path-bias accounting. §7.3 scaling and §7.4 rate tiers are implemented; the
   §7.2 END-echo probe and `pb_dropguards=1` remain explicitly unsupported.
2. Rerun controlled Chutney/current C Tor interoperability for surface Dial,
   onion Dial, service publication, refresh and the new SRV/period rollover and
   maintenance-backoff flows.
3. Review the immutable directory trust boundary and expand CERTS/parser negative
   and concurrency tests.
4. Record benchmark baselines and profiles, then optimize only measured costs.
5. Add unsupported capabilities only with their corresponding spec review and
   interoperability tests: bridge-aware guard state instances, IPv6 streams,
   normal consensus server-descriptor hydration and high-level authorized
   services.

Correctness, explicit validation and readable/auditable code take priority over
speculative optimizations. Performance and fingerprinting claims require
measurements; being embedded is not evidence of either.

Protocol source of truth: [Tor specifications](https://spec.torproject.org/intro/index.html).
