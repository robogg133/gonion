# Embedded Tor over a pinned Snowflake bridge

Run from the repository root:

```sh
go run ./examples/embed/snowflake -timeout 8m
```

This authenticates a bridge, fetches/authenticates/hydrates the microdesc
consensus, then requests `https://example.com/` through a three-hop circuit
whose first hop is **that same bridge**. Onion Dial and Listen use the same
bridge policy. No external Tor, local proxy/listening socket, direct Tor guard
fallback, identity-check bypass or application key/cache file is used.

The public broker, fronts, ICE servers and RSA fingerprint follow `client/torrc`
in the installed Snowflake dependency at `aff631a5b504`. They are visible options,
not a guarantee that those endpoints are reachable from your network. Override
`-broker`, `-fronts`, `-ice`, `-fingerprint`, `-url` and `-timeout` as needed.
The fingerprint must match both the broker's selected bridge and Tor CERTS.
For example, explicitly choose unfronted broker access (a different observable
networking policy, **not an automatic fallback**):

```sh
go run ./examples/embed/snowflake \
  -broker https://snowflake-broker.torproject.net/ -fronts '' -timeout 5m
```

`-verbose` enables transport diagnostics on stderr; they may contain public/local
networking metadata. Defaults use a disabled instance logger and do not change
global application logging. WebRTC discovery involves third-party HTTPS and
ICE/STUN/TURN servers, potentially UDP. `KeepLocalAddresses` stays false.

Use the same options from any application:

```go
opts := embed.DefaultBridgeOptions(embed.BridgeOptions{
    Identity: bridgeRSAFingerprint,
    DialContext: func(ctx context.Context) (net.Conn, error) {
        return snowflake.DialContext(ctx, transportConfig)
    },
})
client, err := embed.New(ctx, opts)
```

The caller owns the selected bridge identity/configuration. Onion service identity
and durable publication revisions remain caller-owned as documented in
[`pkg/embed`](../../../pkg/embed/README.md). Do not substitute a bridge inside a
`GuardDialer` called with a different public guard.

The upstream Snowflake API has no context or transport-wide Close method.
Cancellation stops waiting and closes late connections, but in-flight upstream
NAT probes can outlive it. A returned connection outlives its dial context.

## Opt-in interoperability

```sh
GONION_TEST_SNOWFLAKE=1 GONION_TEST_ONION=1 \
GONION_SNOWFLAKE_BROKER=https://snowflake-broker.torproject.net/ \
GONION_SNOWFLAKE_FRONTS='' \
go test -race ./internal/tests -run '^TestEmbedDialSnowflake$' -count=1 -timeout 10m -v
```

To publish/test a **fresh disposable** onion identity through the bridge, also
set `GONION_TEST_SERVICE=1` and select `^TestEmbedListenOnion$` with `-timeout 15m`.
`GONION_TEST_REFERENCE_TOR=1` adds an independently installed C Tor test client;
it is never the Go client's runtime dependency. These tests make public-network
requests/publications and are disabled by default. Successful tests do not
establish anonymity or censorship resistance.

One configured bridge is supported. Full persistent multi-bridge guards,
randomized retry/backoff, directory-channel recovery and `family-cert` server
descriptors remain unsupported; see the embedding README and `docs/STATUS.md`.
