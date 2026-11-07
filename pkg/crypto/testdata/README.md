# CERTS chain fixtures

These are fixed bytes captured from a local C Tor 0.4.8.10 relay
(`test000a`, ORPort 127.0.0.1:5100) during its link handshake. The capture
performed a TLS handshake with certificate validation disabled, exchanged
`VERSIONS` cells, and read the first `CERTS` cell with Gonion's cell framer
(`pkg/cells/base`). No Gonion certificate verification or parser generated
these bytes; they are the relay's own link-handshake output.

The chain covers certificate types 2 (RSA identity X.509), 4 (identity ->
Ed25519 signing), 5 (signing -> TLS link certificate digest) and 7 (RSA ->
Ed25519 cross-certificate). `tls.bin` is the TLS peer certificate whose
SHA-256 appears in type 5. The relay's authenticated RSA identity is
`D2DB1E509E40B611B6FC6491B4927260AEA24164`, matching the chutney authority
fingerprint.

Extraction command:

```sh
cd /tmp/scratchpad/capture && go run . 127.0.0.1:5100
```

The capture program source is outside the repository (`/tmp/scratchpad/capture`);
it was not added to Gonion and is not part of the test binary.

SHA-256:

- `cert2.der`: `260c58816f6b62f80faf454eb8d0cdff6d894aacaa34589555ccef5ad517ff5e`
- `cert4.bin`: `7f2c3f217c91be2886b8a029528ec863db147a3c983ecfbdccb56b07c892f441`
- `cert5.bin`: `745199e7e96c58929bff6103852fbd8697672d81b0752d420887493b4850d5b8`
- `cert7.bin`: `50f714769242ea91518bbfad211fdfc0dd64d345daa5e96f477ea7f1cb475178`
- `tls.bin`: `c4c8ed171ecc44c29e08c75a8a3e5bea31193ab06fcb4028c2ac00a2101b2253`

Negative variants are derived in the tests by deterministic truncation, reflected
field flips, reordering, and re-sign-neighbor swaps of these positive bytes.
All-zero and other pure-negative inputs are additionally rejected. Tor source:
https://gitlab.torproject.org/tpo/core/tor (runtime 0.4.8.10).
