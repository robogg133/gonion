# Embedded client examples

Runnable applications for [`pkg/embed`](../../pkg/embed). They use the **real Tor
network** when invoked and are not anonymity guarantees. Ordinary Go tests
compile these commands and run offline helper tests; they do not run live flows.

`basic`, `exit`, `onion` and `listen` explicitly permit direct TCP connections to
public fallback/guard relays. `ORDialer` selects the bootstrap connection and its
expected identity; `GuardDialer` connects to each selected traffic guard. This
choice is made here in the application, not silently inside the embedded library.
Repository-internal fallback data is used only because these examples belong to
this module; external applications must provide their own bootstrap policy.

| Command | Behavior |
| --- | --- |
| `go run ./examples/embed/basic` | HTTP GET through an exit with `HTTPClient` |
| `go run ./examples/embed/exit` | Raw `DialContext` and an HTTP/1.0 request, with a stream deadline |
| `go run ./examples/embed/onion` | HTTP GET from the Tor Project's public onion website; `-onion` overrides the host |
| `go run ./examples/embed/listen` | Publish a temporary onion identity and serve HTTP on its Tor-backed listener |

## Ephemeral Listen

The listener example creates a fresh Ed25519 identity for every run and keeps its
revision counter only in application memory. It writes no keys and opens no local
listening socket. The printed URL is available after introduction establishment
and publication acknowledgement, not after a reachability probe. Ctrl-C stops new
acceptance and allows up to 15 seconds for HTTP shutdown before Client.Close
terminates the remaining circuits.

Do **not** reuse its in-memory revision policy with a persistent identity. For a
stable onion address, load/store the identity yourself and atomically persist
monotonically increasing revision reservations before returning them to Listen.
See the [ownership and lifecycle contract](../../pkg/embed/README.md#listen-without-a-local-socket).

## Pluggable transport bootstrap only

```sh
go run ./examples/embed/transport/obfs4 \
  -addr <ip:port> -nodeid <transport-node-id> -cert <obfs4-cert> \
  -fingerprint <expected-tor-rsa-fingerprint> -iatmode 0
```

Each transport has a separate command under `transport/`: `obfs4`, `meek`,
`snowflake` and `webtunnel`, each with its own `main.go`.
See [transport examples](transport/README.md) for commands and parameters for all
four, plus the cancellation limitations of transports without `DialContext`.

The example bootstraps the authenticated directory through the chosen transport and then exits.
It intentionally supplies **no GuardDialer**, so it cannot accidentally send
application traffic directly and bypass a bridge-only policy. The expected Tor
RSA fingerprint is explicit and separate from transport authentication material.

Bridge-aware persistent guard selection remains unimplemented. Supplying a fixed
bridge as the bootstrap transport or substituting it for an arbitrary selected
guard is not an end-to-end bridge integration. No live transport interoperability claim
is made by this example.
