package hs

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// v3 onion address: base32(PUBKEY[32] || CHECKSUM[2] || VERSION[1]) + ".onion".
//
//	CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]
//
// rend-spec §ONIONADDRESS.
const (
	hsVersion = 3
	hsCheck   = ".onion checksum"
	hsSuffix  = ".onion"
)

const (
	pub25519Len = 32
	checkLen    = 2
	rawAddrLen  = pub25519Len + checkLen + 1 // 35
)

var errInvalidAddr = errors.New("hs: invalid onion address")
var errChecksum = errors.New("hs: checksum mismatch, not a valid onion address")
var errTorsion = errors.New("hs: pubkey has a torsion component, rejected")

// ed25519 group order L (little-endian; matches tor ed25519_ref10 modm_m). For
// a valid ed25519 point L*P == identity; any other result means the pubkey has
// a torsion component (rend-spec §4.1).
var ed25519GroupOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// OnionAddr is a validated v3 (.onion) address.
type OnionAddr struct {
	PublicKey ed25519.PublicKey // KP_hs_id, 32 bytes
}

// String returns the canonical lowercase ".onion" form.
func (a OnionAddr) String() string {
	s, _ := EncodeOnionAddr(a.PublicKey)
	return s
}

// EncodeOnionAddr encodes an ed25519 identity public key as a v3 .onion
// address string, per rend-spec §ONIONADDRESS.
func EncodeOnionAddr(pk ed25519.PublicKey) (string, error) {
	if len(pk) != pub25519Len {
		return "", errors.New("hs: ed25519 public key must be 32 bytes")
	}
	raw := make([]byte, 0, rawAddrLen)
	raw = append(raw, pk...)
	sum := hash(pk, hsVersion)
	raw = append(raw, sum[:checkLen]...)
	raw = append(raw, hsVersion)

	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	var sb strings.Builder
	sb.Grow(len(enc) + len(hsSuffix))
	for _, r := range enc {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		sb.WriteRune(r)
	}
	sb.WriteString(hsSuffix)
	return sb.String(), nil
}

// ParseOnionAddr validates a v3 .onion address string and returns its identity
// public key. It rejects malformed base32, a wrong version, a bad checksum,
// and public keys with a torsion component (rend-spec §4.1).
func ParseOnionAddr(addr string) (OnionAddr, error) {
	var zero OnionAddr
	lower := strings.ToLower(strings.TrimSpace(addr))
	if !strings.HasSuffix(lower, hsSuffix) {
		return zero, errInvalidAddr
	}

	upper := strings.ToUpper(strings.TrimSuffix(lower, hsSuffix))
	blob, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upper)
	if err != nil || len(blob) != rawAddrLen {
		return zero, errInvalidAddr
	}

	pk := blob[:pub25519Len]
	if blob[rawAddrLen-1] != hsVersion {
		return zero, errInvalidAddr
	}
	sum := hash(pk, hsVersion)
	if !bytes.Equal(blob[pub25519Len:rawAddrLen-1], sum[:checkLen]) {
		return zero, errChecksum
	}
	if hasTorsion(pk) {
		return zero, errTorsion
	}
	return OnionAddr{PublicKey: pk}, nil
}

// hash returns CHECKSUM = SHA3-256(hsCheck || PUBKEY || VERSION).
func hash(pk []byte, version byte) [32]byte {
	h := sha3.New256()
	h.Write([]byte(hsCheck))
	h.Write(pk)
	h.Write([]byte{version})
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hasTorsion reports whether p, multiplied by the group order L, != identity
// (rend-spec §4.1). We multiply with a Montgomery double-and-add on the raw
// 256-bit integer L because filippo's ScalarMult reduces scalars mod L, which
// would turn [L]P into the useless [0]P.
func hasTorsion(pubkey []byte) bool {
	var p edwards25519.Point
	if _, err := p.SetBytes(pubkey); err != nil {
		return true
	}

	acc := edwards25519.NewIdentityPoint()
	tmp := edwards25519.NewIdentityPoint()
	var l [32]byte
	copy(l[:], ed25519GroupOrder[:])
	for i := 255; i >= 0; i-- {
		tmp.Add(acc, acc) // 2*acc
		acc.Set(tmp)
		if (l[i/8]>>(i%8))&1 == 1 {
			tmp.Add(acc, &p) // acc + p
			acc.Set(tmp)
		}
	}
	// valid (prime-order) points yield the identity; torsion points do not.
	return acc.Equal(edwards25519.NewIdentityPoint()) != 1
}
