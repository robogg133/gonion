# Embedded bootstrap with pluggable transports

Each transport has its own directory and executable `main.go`:
`obfs4/`, `meek/`, `snowflake/` and `webtunnel/`. There is no combined command
or `-transport` flag. Run from the repository root:

```sh
go run ./examples/embed/transport/obfs4 -h
```

Every invocation requires `-fingerprint` and `-guard-state`: the expected Tor bridge RSA identity and a caller-owned public guard-state file,
exactly 40 hexadecimal digits (not all zero). Obtain it and the transport
parameters from your bridge provider. A transport certificate, a front domain,
or a broker URL does not replace the Tor identity check. Values below are
placeholders, not working bridges; the example does not discover bridge secrets.

## obfs4

```sh
go run ./examples/embed/transport/obfs4 \
  -addr "$BRIDGE_ADDR" -nodeid "$OBFS4_NODE_ID" -cert "$OBFS4_CERT" \
  -iatmode 0 -fingerprint "$BRIDGE_RSA_FINGERPRINT" -guard-state ./guards.json
```

`-addr`, `-nodeid` and `-cert` retain the existing example's interface. Transport
argument validation is performed by the obfs4 library. `-iatmode` defaults to 0.

## meek

```sh
go run ./examples/embed/transport/meek \
  -url "$MEEK_URL" -front "$MEEK_FRONT" \
  -fingerprint "$BRIDGE_RSA_FINGERPRINT" -guard-state ./guards.json
```

`-url` is required. Omit `-front` when not using domain fronting. The front changes
the connection destination and TLS SNI while preserving the endpoint HTTP Host.
The bridge-line TCP address is not used by meek. Prefer an HTTPS endpoint.

## Snowflake

```sh
go run ./examples/embed/transport/snowflake \
  -broker "$SNOWFLAKE_BROKER_URL" -front "$SNOWFLAKE_FRONT" \
  -ice "$SNOWFLAKE_ICE_URLS" -fingerprint "$BRIDGE_RSA_FINGERPRINT" -guard-state ./guards.json
```

`-broker` defaults to the package's `snowflake.DefaultBroker`; omit the flag to
use it. `-front` is optional. `-ice` is required and contains comma-separated
STUN/TURN URLs supplied by your deployment (for example the URL syntax
`stun:stun.example:3478`). The same bridge fingerprint is passed to Snowflake's
broker configuration and to Gonion's Tor CERTS verification. No TCP bridge
address is supplied: Snowflake discovers proxies through the broker. WebRTC/NAT
traversal can involve UDP and third-party ICE servers; this is not an HTTPS-only
networking policy. The example keeps local SDP addresses disabled.

Snowflake defaults use a disabled instance logger; they do not change the
process-global standard logger. This bootstrap-only command overrides the
preset fronts with `-front`. For complete bootstrap **and traffic** bridge
routing, use [`../snowflake`](../snowflake) instead.

## WebTunnel

```sh
go run ./examples/embed/transport/webtunnel \
  -url "$WEBTUNNEL_URL" -fingerprint "$BRIDGE_RSA_FINGERPRINT" -guard-state ./guards.json
```

Use the complete HTTPS endpoint URL, including its bridge-specific path.
Optional flags:

- `-addr`: override the TCP endpoint (`host:port`); otherwise resolve the URL host.
- `-servername`: override TLS server name and HTTP Host.
- `-cert`: base64 certificate-chain pin supported by the WebTunnel package;
  omit it to use normal certificate verification. This is not an obfs4 cert.

## Scope and cancellation

Each command downloads and authenticates a consensus over its transport,
prints its flavor, and closes the client. It writes no cache and performs no
application request. It explicitly sets `GuardDialer = nil` even if
`embed.DefaultOptions()` supplies a direct dialer. The supplied state file must
be exclusively owned by this process or protected by a caller-provided lock. There is no automatic fallback
to another transport or direct Tor connection.

Bridge-aware persistent guard selection is not implemented. Configuring only
`ORDialer` does **not** route all traffic through the bridge; substituting a bridge
for an unrelated selected guard would violate relay identity/path checks. These
are bootstrap examples, not end-to-end censorship-resistance or anonymity claims.

`-timeout` defaults to `3m`. obfs4 supports native context cancellation. The other
packages are adapted through `Dial` here: the example adapter stops waiting
on cancellation and closes any connection returned late, but cannot interrupt
all underlying dial/HTTP/WebRTC work. Such work may remain until this one-shot
process exits. Do not treat the adapter as complete transport cancellation for a
long-running embedded application. Canceling a completed dial does not close its
returned connection; the embedded client owns it.

## Offline verification

```sh
go test -race ./examples/embed/transport/... -count=1
go run ./examples/embed/transport/obfs4 -h
go run ./examples/embed/transport/meek -h
go run ./examples/embed/transport/snowflake -h
go run ./examples/embed/transport/webtunnel -h
```

Tests check each executable's help and required parameters, RSA identity pins, absence
of direct traffic dialers, pre-cancellation, late-connection cleanup and returned
connection ownership. They use in-memory pipes and do not contact public bridges.
Compilation and these tests do not establish live interoperability. Running a
configured command makes real network requests; no live bridge test is enabled
by default.
