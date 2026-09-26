# Embedded client

Experimental pure-Go Tor client and onion-v3 service. No local SOCKS proxy,
listening socket or external Tor daemon is required by the implementation.
**Do not use it as an anonymity boundary:** persistent guard selection and a
full security review remain outstanding. See the detailed
[implementation status](../hs/IMPLEMENTATION_STATUS.md), including real
interoperability results and remaining limitations.

## Defaults and caller-owned policy

`DefaultOptions()` sets a 10-minute circuit reuse lifetime and 100 successful
streams per circuit. Zero option values use those defaults; negative limits are
rejected. These are local pool policies, not Tor's complete guard/dirtiness
algorithm. No dialer, disk directory, identity or listener is chosen implicitly.

- `ORDialer(ctx)` opens **only the bootstrap connection** and must honor ctx.
- `BootstrapIdentity` is its expected 20-byte RSA relay fingerprint. It is
  mandatory unless the returned connection implements
  `ExpectedRelayIdentity() [20]byte`, as the built-in fallback dialer does.
  Conflicting pins, zero pins and a CERTS identity mismatch fail closed.
- `GuardDialer(ctx, guard)` opens the selected first relay for every traffic
  circuit, including onion directory, introduction and rendezvous circuits. It
  must honor cancellation and must not substitute another relay.
- There is **no implicit direct TCP fallback**. With nil `GuardDialer`, directory
  bootstrap can finish but traffic circuit construction fails. A fixed bridge
  requires bridge-aware guard selection, which is not implemented; a bootstrap
  transport alone is not a bridge policy for the rest of the client.
- `Storage` is optional and caller-owned. The client neither closes it nor
  chooses an application data directory. The caller owns any key/revision store
  separately from the public consensus cache.

`New(ctx, opts)` dials and bootstraps. `NewWithConn(ctx, conn, opts)` takes ownership
of an existing OR connection, including closing it on error; the same identity
pin requirement applies. Constructors and Listen use their context for
initialization, not the lifetime of successfully returned objects.

**Migration:** raw OR/custom transport callers must supply `BootstrapIdentity`;
callers that only supplied `ORDialer` must now explicitly supply `GuardDialer` to
allow traffic. The fallback dialer carries its selected relay's pin automatically.
Do not replace identity validation with an insecure TLS setting.

## Dial and HTTP

- `DialContext(ctx, "tcp", "host:port")` and `"tcp4"` return `net.Conn` over a
  three-hop circuit. IPv6 exit streams and non-TCP networks are rejected.
- A validated `.onion:port` destination uses introduction/rendezvous rather than
  an exit stream. Onion streams use dedicated circuits, closed with their conn.
- Dial context cancellation interrupts pending work. Use connection deadlines
  for subsequent reads/writes; canceling a completed Dial does not close it.
- `HTTPClient()` supplies a standard `http.Client` with Tor-backed `DialContext`.
  TLS remains in `net/http`, preserving certificate verification and caller TLS
  configuration. Environment HTTP proxies are not used. Set request contexts or
  a client timeout in the application.
- Expired/unauthenticated consensus prevents new paths **and exit-pool reuse**.
  Already accepted/open streams can drain. Circuit TTL also prevents new reuse,
  rather than aborting active traffic solely because time elapsed.

The low-level root `Circuit.Dial` is not an onion-service coordinator: use the
embedded client's DialContext for onion destinations.

## Listen without a local socket

```go
type ServiceOptions struct {
    Identity     ed25519.PrivateKey
    Port         uint16
    NextRevision func(context.Context, [32]byte) (uint64, error)
}
```

`Client.Listen(ctx, opts)` returns `*embed.Listener`, which implements
`net.Listener`. `Accept` returns genuine Tor-backed connections and `Addr()` is
`onion-address:virtual-port` with network `"tor"`. Pass it directly to
`http.Server.Serve`; do not call `net.Listen` or set up a loopback forwarding port.
One virtual port is served per listener/identity. Do not concurrently publish the
same identity through independent listeners with conflicting descriptors.

The application must:

1. Generate or load a valid online Ed25519 identity and keep it private. Listen
   clones it and does not mutate caller storage. No key file is created.
2. Implement `NextRevision`: **atomically reserve and persist** a revision for the
   supplied blinded public key before returning it. It must be strictly greater
   than earlier reservations for that key, including across restarts and failed
   publications. Return storage errors; never silently reset or reuse counters.
3. Honor the callback's context and coordinate concurrent publishers. Different
   services/listeners may call application storage concurrently.
4. Keep the client alive, close accepted connections, and monitor `Listener.Err()`
   for the latest maintenance failure. Successful renewal clears that error.

A process-local counter is appropriate **only for a new identity discarded on
shutdown**. A persisted identity requires persisted revisions. Temporary intro
and descriptor-signing keys and bounded replay caches are internal, in memory;
no guarantee of secure Go heap erasure is made.

Listen waits for introduction establishment and acknowledged publication for both
overlapping descriptors. It is not a reachability probe. Its initialization
context can be canceled after success without killing the listener.

| Operation | New acceptance/publication | Already accepted connections |
| --- | --- | --- |
| `Listener.Close()` | Stops; blocked Accept returns `net.ErrClosed` | Preserved |
| `Listener.Shutdown()` | Stops | Terminated |
| `Client.Close()` | Stops all owned work | Terminated, even after Listener.Close |

## Consensus cache and download flavors

The directory request's flavor must match the returned document. Embedded
bootstrap requests **microdesc**, verifies authority quorum, then hydrates relays
from microdescriptor bytes whose SHA-256 digests match that signed consensus.
The normal `ns` parser is not applied with microdesc column assumptions.

The `pkg/storage/storages/tor` store keeps different formats in different files:

| File | Contents |
| --- | --- |
| `cached-consensus` | Original signed `ns` consensus text, with SHA-1 server-descriptor references |
| `cached-microdesc-consensus` | Original signed microdesc consensus text, with SHA-256 microdescriptor references |
| `gonion-consensus.json` | Gonion's hydrated model plus original signed document, authority certificates and descriptor bytes |

**Neither consensus alone includes all relay keys.** The JSON file is a richer
local cache, not another signed Tor document or an authentication assertion.
On load, bootstrap reauthenticates the signed bytes and rechecks descriptor
hashes; cached flags, keys and hydration booleans are not trust evidence.
Flavor-mismatched cache filenames are rejected instead of silently relabeled.
Legacy JSON stored as `cached-consensus` is not treated as Tor text.

Writes use temporary files, file sync and rename. A snapshot carries its own
original document so separate file replacement cannot mix consensus epochs.
Use a dedicated application directory rather than a running C Tor instance's
data directory. In-memory storage and independent snapshots are also supported.
Snapshots returned by `Consensus()` are copies; treat an authenticated snapshot
as immutable because its exported model fields are not sealed by the API.

Refresh retains the last good snapshot on failure; once it expires, new traffic
fails closed. Automatic recovery after loss of the bootstrap refresh channel
still needs implementation. Full `ns` server-descriptor hydration is not supported.

## Runnable examples and validation

See [`../../examples/embed`](../../examples/embed): direct-network HTTP, raw TCP,
onion Dial, ephemeral HTTP onion Listen, and obfs4 **bootstrap-only** examples.
They deliberately select networking policy in the application. Their use of
repository `internal` fallback data is for examples within this module; external
applications supply their own approved bootstrap endpoints/transport policy.

Default tests are offline:

```sh
go test ./...
go vet ./...
go test -race ./...
```

Opt-in tests make public network requests and may publish a temporary onion:

```sh
GONION_NETWORK_TESTS=1 go test -race ./internal/tests -run '^TestEmbedDialExit$' -count=1 -v -timeout 5m
GONION_TEST_ONION=1 go test -race ./internal/tests -run '^TestEmbedDialOnion$' -count=1 -v -timeout 5m
GONION_TEST_SERVICE=1 GONION_TEST_REFERENCE_TOR=1 go test -race ./internal/tests -run '^TestEmbedListenOnion$' -count=1 -v -timeout 13m
```

The last command optionally runs an independently installed C Tor test client.
It is not needed to embed Gonion. Passing these tests demonstrates only the
specific exercised flows, not full compliance or anonymity.
