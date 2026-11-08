# Security policy

Gonion is experimental and **must not be used as an anonymity boundary**. Persistent
public guards, the immutable trust boundary and path-bias accounting are implemented,
but no independent security audit has been completed and no anonymity,
censorship-resistance or full torspec-compatibility claim is made.

## Reporting

Report suspected vulnerabilities privately rather than opening a public issue with
exploit details. Contact the maintainer through the repository owner's published
channel and include:

- affected files/symbols and a minimal reproduction,
- whether the issue requires a crafted peer/consensus/cache input,
- expected versus actual behavior.

Fixes are tracked with a public security note when a stable release notes entry is made.

## Scope and trust boundaries

- **Consensus/certificate hashes and pins are security-critical.** Never accept a
  consensus, certificate, or identity without explicit validation; reports about
  weakening of `/tor/server/authority.z` pinning, CERTS chain checks, authority
  quorum, descriptor digest or blinded-identity derivation have the highest priority.
- **Guard state (`path.GuardManager`) persistence is caller-owned.** A failed save
  poisons the manager by design; reports must account for that contract.
- **Path-bias counters are deliberately conservative** where the §7.2 END-echo probe
  is not implemented. §7.3 scaling and §7.4 rate tiers are implemented; the probe
  and `pb_dropguards=1` remain explicitly unsupported and fail closed. See the
  `shortcut:` comments and `pkg/hs/IMPLEMENTATION_STATUS.md`.
- Out-of-scope features (IPv6 exits, multi-bridge selection, authorized onion
  services, congestion-control/PoW negotiation, multi-port routing, full ns
  hydration) fail closed by design and are not attack surface work requests.

Known limitations are summarized in
[pkg/hs/IMPLEMENTATION_STATUS.md](pkg/hs/IMPLEMENTATION_STATUS.md) and the current
tests. No release claim should exceed that evidence. The optional log writer and
`Stats` snapshot are privacy-safe by design: they carry failure classes and
counters, never private keys, cookies, descriptor plaintext, or destination
labels.
