package hs

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// Key-derivation for v3 onion services: credential / subcredential and the
// per-time-period key blinding, rend-spec §SUBCRED and §KEYBLIND.
//
//	h = SHA3-256(BLIND_STRING || pubkey || s || BASE || NONCE)
//	  BLIND_STRING = "Derive temporary signing key\x00"   (trailing NUL is real)
//	  BASE         = ASCII coordinates of the ed25519 basepoint, exactly as in
//	                 tor hs_common.c build_blinded_key_param().
//	  NONCE        = "key-blind" || INT_8(period_num) || INT_8(period_len)
const (
	blindStringNul = "Derive temporary signing key\x00"
	blindHashInput = "Derive temporary signing key hash input"
	noncePrefix    = "key-blind"
	baseASCII      = "(15112221349535400772501151409588531511" +
		"454012693041857206046113283949847762202, " +
		"463168356949264781694283940034751631413" +
		"07993866256225615783033603165251855960)"
	credentialString = "credential"
	subcredentialKey = "subcredential"

	expandedSecretKeyLen = 64 // ed25519 expanded secret: scalar(32) || rh(32)
)

var errBlinding = errors.New("hs: key blinding failed")

// Credential returns SHA3-256("credential" || identity-pubkey).
func Credential(identity ed25519.PublicKey) [32]byte {
	h := sha3.New256()
	h.Write([]byte(credentialString))
	h.Write([]byte(identity))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Subcredential returns SHA3-256("subcredential" || credential ||
// blinded-public-key), per rend-spec §SUBCRED.
func Subcredential(identity, blinded ed25519.PublicKey) [32]byte {
	cred := Credential(identity)
	h := sha3.New256()
	h.Write([]byte(subcredentialKey))
	h.Write(cred[:])
	h.Write(blinded)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BlindingParameter returns the unclamped 32-byte blinding factor h. secret is
// the optional 's' (nil when unused), per §KEYBLIND.
func BlindingParameter(identity ed25519.PublicKey, secret []byte, periodNum uint64, periodLenMin int) ([32]byte, error) {
	if len(identity) != pub25519Len {
		return [32]byte{}, errBlinding
	}
	if periodLenMin <= 0 {
		periodLenMin = DefaultPeriodLengthMinutes
	}

	h := sha3.New256()
	h.Write([]byte(blindStringNul))
	h.Write([]byte(identity))
	if secret != nil {
		h.Write(secret)
	}
	h.Write([]byte(baseASCII))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], periodNum)
	h.Write([]byte(noncePrefix))
	h.Write(be[:])
	binary.BigEndian.PutUint64(be[:], uint64(periodLenMin))
	h.Write(be[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// BlindedPublicKey derives the period's blinded identity public key from the
// master identity public key, per §KEYBLIND: A' = A * clamp(h).
func BlindedPublicKey(identity ed25519.PublicKey, secret []byte, periodNum uint64, periodLen int) (ed25519.PublicKey, error) {
	param, err := BlindingParameter(identity, secret, periodNum, periodLen)
	if err != nil {
		return nil, err
	}
	tweak, err := blindedScalar(param)
	if err != nil {
		return nil, err
	}
	var base edwards25519.Point
	if _, err := base.SetBytes([]byte(identity)); err != nil {
		return nil, err
	}
	var out edwards25519.Point
	out.ScalarMult(tweak, &base)
	return ed25519.PublicKey(out.Bytes()), nil
}

// BlindSecretKey derives the 64-byte blinded ed25519 secret key from a 32-byte
// master seed. The first 32 bytes are clamp(h)*scalar mod q, the last 32 are RH'.
func BlindSecretKey(seed []byte, secret []byte, periodNum uint64, periodLenMin int) ([]byte, error) {
	if len(seed) != pub25519Len {
		return nil, errors.New("hs: ed25519 seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := ed25519.PublicKey(priv[pub25519Len:])

	param, err := BlindingParameter(pub, secret, periodNum, periodLenMin)
	if err != nil {
		return nil, err
	}
	tweak, err := blindedScalar(param)
	if err != nil {
		return nil, err
	}

	expanded := sha512.Sum512(seed)
	var scalarBytes [pub25519Len]byte
	copy(scalarBytes[:], expanded[:pub25519Len])
	scalar, err := blindedScalar(scalarBytes)
	if err != nil {
		return nil, err
	}

	// a' = clamp(h) * scalar mod q
	var ap edwards25519.Scalar
	ap.Multiply(tweak, scalar)

	out := make([]byte, 0, expandedSecretKeyLen)
	ab := ap.Bytes()
	out = append(out, ab[:pub25519Len]...)

	// RH' = SHA512-256 of (blindHashInput || RH)
	rh := sha512.Sum512(append([]byte(blindHashInput), expanded[pub25519Len:]...))
	out = append(out, rh[:pub25519Len]...)
	return out, nil
}

// blindedScalar clamps b to an ed25519 scalar (SetBytesWithClamping).
func blindedScalar(b [32]byte) (*edwards25519.Scalar, error) {
	b[0] &= 248
	b[31] &= 63
	b[31] |= 64
	return new(edwards25519.Scalar).SetBytesWithClamping(b[:])
}
