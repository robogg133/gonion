# HS v3 descriptor APIs

This package implements the signed v3 outer wrapper, Ed25519 certificates
(types 08, 09, 0B), both SHAKE256/AES-256-CTR/SHA3-256-MAC encryption layers,
16-byte descriptor-cookie client authorization, and bounded introduction-point
parsing. The previous private Gonion format is **not supported**.

## Service integration

1. Derive the period key with
   `crypto.BlindPrivateKey(identity ed25519.PrivateKey, periodNumber, periodLength uint64)`.
   The period length is **minutes**, not seconds. Choose periods from the
   authenticated consensus and the service's overlapping-descriptor schedule.
2. Generate a separate standard `ed25519.PrivateKey` for descriptor signing.
3. Call `desc.Encode(desc.EncodeOptions{...})`, which returns `([]byte, error)`.
   Required fields are `BlindedKey`, `SigningKey`, `CertificateExpiry`, and each
   introduction point's keys and link specifiers. `LifetimeMinutes == 0` selects
   Tor's 180-minute default. Zero introduction points are valid; the maximum is 20.
4. Persist/increase `RevisionCounter` for each blinded public key. Revision zero
   is valid. No timestamp or process-local counter is silently substituted.
5. Publish the returned bytes through a dedicated anonymous HSDir circuit to
   `/tor/hs/3/publish`. Circuit creation, selection and publication scheduling
   belong to the service, not this encoding package.

`EncodeOptions.AuthorizedClients` is `[]*ecdh.PublicKey` containing X25519 keys;
leave it empty for a public service. Both cases have fresh ephemeral keys,
fresh hashed salts, shuffled auth-client records in multiples of 16, and outer
plaintext padding in 10000-byte blocks.

For offline blinded signing, call
`desc.SigningCertificate(blindedPrivateKey, descriptorSigningPublicKey, expiry)`
once. Give the online encoder `EncodeOptions.BlindedPublicKey` and
`SigningKeyCertificate` instead of `BlindedKey`. Certificates are **binary**,
not PEM strings. Keep the blinded private key offline: its compromise can
also compromise the master identity key.

## Client/coordinator integration

- `desc.Decode(raw []byte, blinded *crypto.BlindedPublicKey,
  clientAuth *ecdh.PrivateKey, now time.Time) (*desc.Descriptor, error)` checks
  the expected blinded key, certificate expiry, certificate signatures, outer
  signature, both MACs, and introduction certificates before returning points.
  `clientAuth` is nil for public services. `ErrClientAuthorization` identifies
  failure to open a client-authorized inner layer.
- `desc.Fetch` retains its previous signature. `desc.FetchAuthorized` additionally
  takes an optional X25519 client private key. Both use
  `circ.NewStream("dir", circ.HopCount()-1)` (Gonion's BEGIN_DIR convention),
  `/tor/hs/3/` followed by **unpadded standard base64 of the blinded public key**,
  bounded HTTP headers/body, and cancellation of the dedicated circuit. The
  supplied relay must advertise the HSDir flag and HSDir=2 capability.
- The circuit **must already end at the selected HSDir** and must be dedicated
  to this fetch, with at least three hops. Passing an HSDir argument does not
  extend or retarget a circuit. The current HS client fetch caller needs to
  ensure this contract instead of constructing an unrelated random path.
- `IntroPoint.OnionKey` is the **relay ntor key**, for extension to that relay.
  `IntroPoint.EncKey` is the **service introduction-encryption key**, for
  `crypto.ParseECDHKeys` / HS-ntor. The old client call using `OnionKey` for
  HS-ntor must be migrated to `EncKey`; there is no alias that hides the error.
- `IntroPoint.LinkSpecifiers` retains the entire NSPEC-prefixed wire block,
  including unknown types and original ordering. Forward it verbatim in
  EXTEND2. `LinkSpecs` is a convenience view of known types because the existing
  `lspec.Lspec` type cannot represent unknown types.
- Honor `IntroAuthRequired` before attempting introduction; descriptor client
  authorization and INTRODUCE1 authentication are separate mechanisms.
- Cache users must compare `RevisionCounter` for the same `BlindedKey` and
  reject rollback. Cache expiry is bounded by `LifetimeSeconds` from receipt
  and the earliest `CertificateExpiry`. Decode itself is stateless.
- `desc.Parse(raw)` validates only the self-contained outer wrapper. It cannot
  authenticate which onion address owns an embedded blinded key and returns no
  introduction points. Use `Decode`, not `Parse`, for client connections.

The lower-level encryption API is
`crypto.EncryptDescriptor(secretData, subcredential []byte, revision uint64,
layer crypto.DescriptorLayer, plaintext []byte)` and its inverse
`crypto.DecryptDescriptor(..., blob []byte)`. The layer constants are
`SuperencryptedLayer` and `EncryptedLayer`. The caller supplies outer padding.
The obsolete `DescKeys`, `KdfKeys`, and hashed `DescriptorID` APIs were removed.
Use `crypto.BlindPublicKey` for validation errors; legacy `BlindPk` returns nil
for invalid input rather than panicking.

## Validation and limits

Tests include Tor source vectors and fixtures, public and authorized descriptor
round trips, certificate and layer mutations, HTTP cancellation/limits, and
parser fuzz seeds. See `testdata/README.md` for fixture provenance. Descriptor
size is bounded to 50000 bytes; network tests use in-memory pipes only.

This is not a security audit or live Tor interoperability result. No anonymity,
production readiness, or complete Tor compatibility is implied.
