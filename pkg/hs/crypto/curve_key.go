package crypto

import (
	"bytes"
	"errors"

	"filippo.io/edwards25519/field"
)

// Ed25519FromX25519 converts a public key using dir-spec appendix C. The sign
// bit is carried by ntor cross-certificates; onion descriptors use sign zero.
func Ed25519FromX25519(raw []byte, sign byte) ([]byte, error) {
	u, err := new(field.Element).SetBytes(raw)
	if err != nil || !bytes.Equal(u.Bytes(), raw) || sign > 1 {
		return nil, errors.New("crypto: invalid Curve25519 key or sign bit")
	}
	one := new(field.Element).One()
	numerator := new(field.Element).Subtract(u, one)
	denominator := new(field.Element).Add(u, one)
	if denominator.Equal(new(field.Element).Zero()) == 1 {
		return nil, errors.New("crypto: degenerate Curve25519 key")
	}
	denominator.Invert(denominator)
	key := new(field.Element).Multiply(numerator, denominator).Bytes()
	key[31] |= sign << 7
	if err := ValidateEd25519PublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}
