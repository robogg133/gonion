package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
)

const BlindString = "Derive temporary signing key\000"
const KeyBlind = "key-blind"
const blindBasePoint = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

type BlindedPublicKey struct {
	pk                         ed25519.PublicKey
	blindPk                    []byte
	periodNumber, periodLenght uint64
}

func nonce(periodNumber, periodLength uint64) []byte {
	n := binary.BigEndian.AppendUint64([]byte(KeyBlind), periodNumber)
	return binary.BigEndian.AppendUint64(n, periodLength)
}

func blindFactor(pk []byte, periodNumber, periodLength uint64) *edwards25519.Scalar {
	h := sha3.New256()
	h.Write([]byte(BlindString))
	h.Write(pk)
	h.Write([]byte(blindBasePoint))
	h.Write(nonce(periodNumber, periodLength))
	s, _ := new(edwards25519.Scalar).SetBytesWithClamping(h.Sum(nil))
	return s
}

// ValidateEd25519PublicKey rejects noncanonical, identity and torsion-bearing keys.
func ValidateEd25519PublicKey(encoded []byte) error {
	p, err := new(edwards25519.Point).SetBytes(encoded)
	if err != nil || !bytes.Equal(p.Bytes(), encoded) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("hs/crypto: invalid Ed25519 public key")
	}
	var eight [32]byte
	eight[0] = 8
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(eight[:])
	s.Invert(s)
	q := new(edwards25519.Point).MultByCofactor(p)
	q.ScalarMult(s, q)
	if q.Equal(p) != 1 {
		return errors.New("hs/crypto: Ed25519 public key has torsion")
	}
	return nil
}

// BlindPublicKey implements rend-spec-v3 [KEYBLIND]. Period length is in minutes.
func BlindPublicKey(pk ed25519.PublicKey, periodNumber, periodLength uint64) (*BlindedPublicKey, error) {
	if err := ValidateEd25519PublicKey(pk); err != nil {
		return nil, err
	}
	if periodLength == 0 {
		return nil, errors.New("hs/crypto: zero period length")
	}
	p, _ := new(edwards25519.Point).SetBytes(pk)
	return &BlindedPublicKey{
		pk:           append(ed25519.PublicKey(nil), pk...),
		blindPk:      new(edwards25519.Point).ScalarMult(blindFactor(pk, periodNumber, periodLength), p).Bytes(),
		periodNumber: periodNumber, periodLenght: periodLength,
	}, nil
}

// BlindPk is the existing convenience API. Invalid input returns nil, never panics.
// New callers should use BlindPublicKey to receive validation errors.
func BlindPk(pk ed25519.PublicKey, periodNumber, periodLength uint64) *BlindedPublicKey {
	k, _ := BlindPublicKey(pk, periodNumber, periodLength)
	return k
}

func (bk *BlindedPublicKey) Bytes() []byte {
	if bk == nil {
		return nil
	}
	return append([]byte(nil), bk.blindPk...)
}
func (bk *BlindedPublicKey) Pk() ed25519.PublicKey {
	if bk == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), bk.pk...)
}

// BlindedPrivateKey is an expanded Ed25519 key, not a standard Ed25519 seed.
// Keep it offline when possible: compromise also compromises the master key.
type BlindedPrivateKey struct {
	public *BlindedPublicKey
	scalar *edwards25519.Scalar
	prefix [32]byte
}

// BlindPrivateKey derives a period key from a standard Go Ed25519 private key.
func BlindPrivateKey(identity ed25519.PrivateKey, periodNumber, periodLength uint64) (*BlindedPrivateKey, error) {
	if len(identity) != ed25519.PrivateKeySize {
		return nil, errors.New("hs/crypto: invalid identity private key length")
	}
	canonical := ed25519.NewKeyFromSeed(identity[:32])
	defer clear(canonical)
	if !bytes.Equal(canonical, identity) {
		return nil, errors.New("hs/crypto: inconsistent identity private key")
	}
	expanded := sha512.Sum512(identity[:32])
	defer clear(expanded[:])
	return blindExpanded(identity[32:], expanded[:], periodNumber, periodLength)
}

func blindExpanded(pk, expanded []byte, periodNumber, periodLength uint64) (*BlindedPrivateKey, error) {
	public, err := BlindPublicKey(pk, periodNumber, periodLength)
	if err != nil {
		return nil, err
	}
	if len(expanded) != 64 {
		return nil, errors.New("hs/crypto: invalid expanded private key")
	}
	a, _ := new(edwards25519.Scalar).SetBytesWithClamping(expanded[:32])
	if !bytes.Equal(new(edwards25519.Point).ScalarBaseMult(a).Bytes(), pk) {
		return nil, errors.New("hs/crypto: inconsistent expanded private key")
	}
	a.Multiply(a, blindFactor(pk, periodNumber, periodLength))
	h := sha512.New()
	h.Write([]byte("Derive temporary signing key hash input"))
	h.Write(expanded[32:])
	k := &BlindedPrivateKey{public: public, scalar: a}
	copy(k.prefix[:], h.Sum(nil)[:32])
	return k, nil
}

func (k *BlindedPrivateKey) PublicKey() *BlindedPublicKey {
	if k == nil {
		return nil
	}
	return k.public
}

// Sign signs a message with the expanded blinded key using ordinary Ed25519.
func (k *BlindedPrivateKey) Sign(message []byte) ([]byte, error) {
	if k == nil || k.scalar == nil || k.public == nil {
		return nil, errors.New("hs/crypto: missing blinded private key")
	}
	h := sha512.New()
	h.Write(k.prefix[:])
	h.Write(message)
	r, _ := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	h.Reset()
	h.Write(R)
	h.Write(k.public.blindPk)
	h.Write(message)
	challenge, _ := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	s := new(edwards25519.Scalar).MultiplyAdd(challenge, k.scalar, r)
	return append(R, s.Bytes()...), nil
}
