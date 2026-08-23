package crypto

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/binary"

	"filippo.io/edwards25519"
)

const BlindString = "Derive temporary signing key\000"

var E25519BasePointLittleEndian = []byte{
	0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
}

const KeyBlind = "key-blind"

type BlindedPublicKey struct {
	pk                         ed25519.PublicKey
	blindPk                    []byte
	periodNumber, periodLenght uint64
}

func nonce(periodNumber, periodLength uint64) []byte {
	n := binary.BigEndian.AppendUint64([]byte(KeyBlind), periodNumber)
	return binary.BigEndian.AppendUint64(n, periodLength)
}

func BlindPk(pk ed25519.PublicKey, periodNumber, periodLength uint64) *BlindedPublicKey {
	s := sha3.New256()
	s.Write([]byte(BlindString))
	s.Write(pk)
	s.Write(E25519BasePointLittleEndian)
	s.Write(nonce(periodNumber, periodLength))

	h := s.Sum(nil)
	// rend-spec-v3 [KEYBLIND]: s[0] &= 248; s[31] &= 63; s[31] |= 64
	clamp := make([]byte, len(h))
	copy(clamp, h)
	clamp[0] &= 248
	clamp[len(clamp)-1] &= 63
	clamp[len(clamp)-1] |= 64

	return &BlindedPublicKey{
		pk:           pk,
		periodNumber: periodNumber,
		periodLenght: periodLength,
		blindPk:      scalarMult(clamp, pk),
	}
}

// scalarMult computes sBytes * A. The scalar is reduced mod the group order
// via SetUniformBytes because a raw hash is almost never a canonical scalar;
// point multiplication only depends on the scalar mod l.
func scalarMult(sBytes []byte, ABytes []byte) []byte {
	var buf [64]byte
	copy(buf[:], sBytes)

	scalar, err := new(edwards25519.Scalar).SetUniformBytes(buf[:])
	if err != nil {
		panic(err) // unreachable: buf is always 64 bytes
	}

	A, err := new(edwards25519.Point).SetBytes(ABytes)
	if err != nil {
		panic(err)
	}

	return new(edwards25519.Point).ScalarMult(scalar, A).Bytes()
}

// 22 de setembro
