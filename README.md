# Gonion

![Gonion](icon.png)

An experimental **pure-Go Tor client and onion-v3 service** designed for embedding.
No CGO, native bindings, `libtor`, external Tor daemon or local SOCKS proxy is
required by the client implementation.

> **Not production-ready or an anonymity boundary.** Persistent guard selection
> is still missing, and no full independent security audit has been completed.
> Successful TCP/HTTPS/onion interoperability tests do not establish anonymity,
> censorship resistance, reduced detectability, or complete Tor compatibility.

## Current functionality

- TLS/OR link negotiation, relay CERTS authentication and expected identity pins.
- Tor cell framing, ntor circuit construction, per-hop cryptography, streams,
  SENDME flow control and deadlines.
- Authenticated consensus download, microdescriptor hydration, refresh and
  separate raw/hydrated cache files.
- `pkg/embed`: `DefaultOptions`, caller-controlled bootstrap/guard dialers and
  storage, TCP/HTTPS/onion Dial, circuit pooling and lifecycle management.
- Onion-v3 descriptor validation, introduction/rendezvous, and service publication.
- A Tor-backed `net.Listener` for onion services, without a local listening socket.
  Service identities and durable descriptor revision allocation belong to callers.
- An obfs4 transport adapter. End-to-end bridge-aware guard selection is not yet
  implemented; using obfs4 for bootstrap alone does not route traffic through it.

See the [embedding guide](pkg/embed/README.md),
[runnable examples](examples/embed/README.md), and
[detailed implementation status and remaining work](pkg/hs/IMPLEMENTATION_STATUS.md).

For the dated development handoff, read [context and decisions](docs/CONTEXT.md),
[current validation and known failures](docs/STATUS.md), and
[the resume plan](docs/NEXT_STEPS.md), in that order. The 2026-09-26 full offline
suite currently fails one ns fixture digest assertion; historical passes do not
supersede this result.

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
| `pkg/path` | Weighted relay selection, family/identity/subnet constraints; persistent guards remain outstanding |
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

1. Implement persistent guard state/persistence and path-bias handling.
2. Recover directory refresh after channel loss; stress long-running service
   rollover, publication failures and restarts.
3. Harden the mutable authenticated-consensus API and expand CERTS/parser/stream
   negative and concurrency tests.
4. Add unsupported capabilities only with their corresponding spec review and
   interoperability tests: bridge-aware guards, IPv6 streams, normal consensus
   server-descriptor hydration and high-level authorized services.

Correctness, explicit validation and readable/auditable code take priority over
speculative optimizations. Performance and fingerprinting claims require
measurements; being embedded is not evidence of either.

Protocol source of truth: [Tor specifications](https://spec.torproject.org/intro/index.html).
