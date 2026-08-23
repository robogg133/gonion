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
	//h.Write(nil)  s (optional secret)
	s.Write(E25519BasePointLittleEndian)
	s.Write(nonce(periodNumber, periodLength))

	h := s.Sum(nil)
	a := make([]byte, len(h))
	for i, b := range h {
		b &= 248
		b &= 63
		b |= 64
		a[i] = b
	}

	return &BlindedPublicKey{
		pk:           pk,
		periodNumber: periodNumber,
		periodLenght: periodLength,
		blindPk:      scalarMult(h, a),
	}
}

func scalarMult(h []byte, ABytes []byte) []byte {
	var hScalar edwards25519.Scalar
	var A edwards25519.Point

	if _, err := hScalar.SetCanonicalBytes(h); err != nil {
		panic(err)
	}

	if _, err := A.SetBytes(ABytes); err != nil {
		panic(err)
	}

	result := new(edwards25519.Point).ScalarMult(&hScalar, &A)

	return result.Bytes()
}

// 22 de setembro
