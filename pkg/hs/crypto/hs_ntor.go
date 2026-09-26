package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// hs-ntor handshake (rend-spec-v3 §NTOR-WITH-EXTRA-DATA). Client side builds
// the INTRODUCE1 ENCRYPTED payload; service side decrypts it and replies with
// the RENDEZVOUS1 handshake info.

const HsNtorProtoID = "tor-hs-ntor-curve25519-sha3-256-1"

const (
	tHsenc    = ":hs_key_extract"
	tHsverify = ":hs_verify"
	tHsmac    = ":hs_mac"
	mHsexpand = ":hs_key_expand"
)

const (
	HsNtorKeySeedLen = 32 // S_KEY_LEN for AES-256
	HsNtorMacLen     = 32 // SHA3-256
)

var (
	hsEncProtoID  = []byte(HsNtorProtoID + tHsenc)
	hsVerifyProto = []byte(HsNtorProtoID + tHsverify)
	hsMacProtoID  = []byte(HsNtorProtoID + tHsmac)
	hsExpandProto = []byte(HsNtorProtoID + mHsexpand)
)

// hsMac implements rend-spec-v3 section 0.3, not HMAC.
func hsMac(key, data []byte) []byte {
	h := sha3.New256()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(key)))
	h.Write(size[:])
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}

// introMACBody covers the entire canonical INTRODUCE1 header, including its
// zero legacy ID and extension count (rend-spec-v3 Appendix G.1). These helpers
// support headers without extensions only; an extended header must not be
// stripped and passed here, since it is part of the authenticated transcript.
func introMACBody(authKey, clientKey, ciphertext []byte) []byte {
	body := make([]byte, 23, 56+len(clientKey)+len(ciphertext))
	body[20] = 2
	body[22] = 32
	body = append(body, authKey...)
	body = append(body, 0)
	body = append(body, clientKey...)
	return append(body, ciphertext...)
}

// shsKDF is the SHAKE256-based KDF used for the hs-ntor key streams.
func shsKDF(key, info []byte, outLen int) []byte {
	out := make([]byte, outLen)
	h := sha3.NewShake256()
	h.Write(key)
	h.Write(info)
	h.Read(out)
	return out
}

// HsClientKeys holds the derived symmetric keys for the client's intro payload.
type HsClientKeys struct {
	ENCKey []byte
	MACKey []byte
}

// HsClientIntro encrypts plaintext (rendezvous cookie + link specifiers etc.)
// for an INTRODUCE1 message. B is the intro point encryption key, authKey the
// intro auth key, subcred the service subcredential. The outer INTRODUCE1
// header must have a zero legacy ID and no extensions.
func HsClientIntro(privX *ecdh.PrivateKey, B *ecdh.PublicKey, authKey, subcred, plaintext []byte) (*HsClientKeys, []byte, error) {
	if privX == nil || B == nil || privX.Curve() != ecdh.X25519() || B.Curve() != ecdh.X25519() || len(authKey) != 32 || len(subcred) != 32 {
		return nil, nil, errors.New("hs-ntor: invalid introduction keys")
	}
	if len(plaintext) > 498-56-32-HsNtorMacLen {
		return nil, nil, errors.New("hs-ntor: introduction exceeds relay payload")
	}
	X := privX.PublicKey()
	expBx, err := privX.ECDH(B)
	if err != nil {
		return nil, nil, err
	}

	secret := make([]byte, 0, 32+len(authKey)+32+32+len(HsNtorProtoID))
	secret = append(secret, expBx...)
	secret = append(secret, authKey...)
	secret = append(secret, X.Bytes()...)
	secret = append(secret, B.Bytes()...)
	secret = append(secret, HsNtorProtoID...)

	info := make([]byte, 0, len(hsExpandProto)+len(subcred))
	info = append(info, hsExpandProto...)
	info = append(info, subcred...)

	keysRaw := shsKDF(secret, append(append([]byte{}, hsEncProtoID...), info...), HsNtorKeySeedLen+HsNtorMacLen)
	encKey := keysRaw[:HsNtorKeySeedLen]
	macKey := keysRaw[HsNtorKeySeedLen:]

	encData, err := aes256Ctr(encKey, plaintext)
	if err != nil {
		return nil, nil, err
	}

	mac := hsMac(macKey, introMACBody(authKey, X.Bytes(), encData))

	out := make([]byte, 0, 32+len(encData)+HsNtorMacLen)
	out = append(out, X.Bytes()...)
	out = append(out, encData...)
	out = append(out, mac...)

	return &HsClientKeys{ENCKey: encKey, MACKey: macKey}, out, nil
}

// HsServiceIntro decrypts a client's intro payload and returns the plaintext
// plus the client public key X. b is the service's introduction encryption
// secret key. The caller must reject nonzero legacy IDs and outer extensions
// before calling this canonical-header helper.
func HsServiceIntro(b *ecdh.PrivateKey, authKey, subcred, blob []byte) (*ecdh.PublicKey, []byte, error) {
	return HsServiceIntroWithHeader(b, authKey, subcred, introMACBody(authKey, nil, nil), blob)
}

// HsServiceIntroWithHeader authenticates the original outer header, including
// unknown, repeated and zero-length extensions, without normalizing it.
func HsServiceIntroWithHeader(b *ecdh.PrivateKey, authKey, subcred, header, blob []byte) (*ecdh.PublicKey, []byte, error) {
	if err := validateIntroHeader(header, authKey); err != nil {
		return nil, nil, err
	}
	if b == nil || b.Curve() != ecdh.X25519() || len(authKey) != 32 || len(subcred) != 32 {
		return nil, nil, errors.New("hs-ntor: invalid introduction keys")
	}
	if len(header)+len(blob) > 498 {
		return nil, nil, errors.New("hs-ntor: introduction exceeds relay payload")
	}
	if len(blob) < 32+HsNtorMacLen {
		return nil, nil, errors.New("hs-ntor: short intro blob")
	}
	X, err := ecdh.X25519().NewPublicKey(blob[:32])
	if err != nil {
		return nil, nil, err
	}
	encData := blob[32 : len(blob)-HsNtorMacLen]
	theirMac := blob[len(blob)-HsNtorMacLen:]

	expXb, err := b.ECDH(X)
	if err != nil {
		return nil, nil, err
	}
	B := b.PublicKey()

	secret := make([]byte, 0, 32+len(authKey)+32+32+len(HsNtorProtoID))
	secret = append(secret, expXb...)
	secret = append(secret, authKey...)
	secret = append(secret, X.Bytes()...)
	secret = append(secret, B.Bytes()...)
	secret = append(secret, HsNtorProtoID...)

	info := make([]byte, 0, len(hsExpandProto)+len(subcred))
	info = append(info, hsExpandProto...)
	info = append(info, subcred...)

	keysRaw := shsKDF(secret, append(append([]byte{}, hsEncProtoID...), info...), HsNtorKeySeedLen+HsNtorMacLen)
	encKey := keysRaw[:HsNtorKeySeedLen]
	macKey := keysRaw[HsNtorKeySeedLen:]

	if subtle.ConstantTimeCompare(hsMac(macKey, append(bytes.Clone(header), blob[:len(blob)-HsNtorMacLen]...)), theirMac) != 1 {
		return nil, nil, errors.New("hs-ntor: intro MAC mismatch")
	}

	plain, err := aes256Ctr(encKey, encData)
	if err != nil {
		return nil, nil, err
	}
	return X, plain, nil
}

// HsServiceRendezvousReply retains the reply-only API for existing callers.
func HsServiceRendezvousReply(X, B *ecdh.PublicKey, authKey []byte, serviceSK *ecdh.PrivateKey, y *ecdh.PrivateKey) ([]byte, error) {
	reply, _, err := HsServiceRendezvous(X, B, authKey, serviceSK, y)
	return reply, err
}

// HsServiceRendezvous returns SERVER_PK|AUTH and the authenticated E2E key seed.
// y must be a fresh single-use keypair for this rendezvous.
func HsServiceRendezvous(X, B *ecdh.PublicKey, authKey []byte, serviceSK *ecdh.PrivateKey, y *ecdh.PrivateKey) ([]byte, []byte, error) {
	if X == nil || B == nil || serviceSK == nil || y == nil || len(authKey) != 32 || X.Curve() != ecdh.X25519() || B.Curve() != ecdh.X25519() || serviceSK.Curve() != ecdh.X25519() || y.Curve() != ecdh.X25519() || !B.Equal(serviceSK.PublicKey()) {
		return nil, nil, errors.New("hs-ntor: invalid rendezvous keys")
	}
	expXy, err := y.ECDH(X)
	if err != nil {
		return nil, nil, err
	}
	expXb, err := serviceSK.ECDH(X)
	if err != nil {
		return nil, nil, err
	}

	rend := make([]byte, 0, 32+32+len(authKey)+32+32+32+len(HsNtorProtoID))
	rend = append(rend, expXy...)
	rend = append(rend, expXb...)
	rend = append(rend, authKey...)
	rend = append(rend, B.Bytes()...)
	rend = append(rend, X.Bytes()...)
	rend = append(rend, y.PublicKey().Bytes()...)
	rend = append(rend, HsNtorProtoID...)

	verify := hsMac(rend, hsVerifyProto)

	auth := make([]byte, 0, len(verify)+len(authKey)+32+32+32+len(HsNtorProtoID)+6)
	auth = append(auth, verify...)
	auth = append(auth, authKey...)
	auth = append(auth, B.Bytes()...)
	auth = append(auth, y.PublicKey().Bytes()...)
	auth = append(auth, X.Bytes()...)
	auth = append(auth, HsNtorProtoID...)
	auth = append(auth, "Server"...)
	authMac := hsMac(auth, hsMacProtoID)

	reply := make([]byte, 0, 32+HsNtorMacLen)
	reply = append(reply, y.PublicKey().Bytes()...)
	reply = append(reply, authMac...)

	return reply, hsMac(rend, hsEncProtoID), nil
}

func validateIntroHeader(header, authKey []byte) error {
	if len(header) < 56 || len(header) > 498-64 || len(authKey) != 32 || !bytes.Equal(header[:20], make([]byte, 20)) || header[20] != 2 || binary.BigEndian.Uint16(header[21:23]) != 32 || !bytes.Equal(header[23:55], authKey) {
		return errors.New("hs-ntor: invalid introduction header")
	}
	pos := 56
	for n := 0; n < int(header[55]); n++ {
		if len(header)-pos < 2 {
			return errors.New("hs-ntor: truncated introduction extension")
		}
		size := int(header[pos+1])
		pos += 2
		if size > len(header)-pos {
			return errors.New("hs-ntor: truncated introduction extension")
		}
		pos += size
	}
	if pos != len(header) {
		return errors.New("hs-ntor: trailing introduction header bytes")
	}
	return nil
}

// HsClientFinishRendezvous validates the service reply and returns the shared
// ntor key seed on the client side.
func HsClientFinishRendezvous(privX *ecdh.PrivateKey, B *ecdh.PublicKey, authKey, reply []byte) ([]byte, error) {
	if privX == nil || B == nil || privX.Curve() != ecdh.X25519() || B.Curve() != ecdh.X25519() || len(authKey) != 32 {
		return nil, errors.New("hs-ntor: invalid rendezvous keys")
	}
	if len(reply) != 32+HsNtorMacLen {
		return nil, errors.New("hs-ntor: short rendezvous reply")
	}
	Y, err := ecdh.X25519().NewPublicKey(reply[:32])
	if err != nil {
		return nil, err
	}
	theirAuth := reply[32:]

	expXy, err := privX.ECDH(Y)
	if err != nil {
		return nil, err
	}
	expXb, err := privX.ECDH(B)
	if err != nil {
		return nil, err
	}
	X := privX.PublicKey()

	rend := make([]byte, 0, 32+32+len(authKey)+32+32+32+len(HsNtorProtoID))
	rend = append(rend, expXy...)
	rend = append(rend, expXb...)
	rend = append(rend, authKey...)
	rend = append(rend, B.Bytes()...)
	rend = append(rend, X.Bytes()...)
	rend = append(rend, Y.Bytes()...)
	rend = append(rend, HsNtorProtoID...)

	ntorKeySeed := hsMac(rend, hsEncProtoID)
	verify := hsMac(rend, hsVerifyProto)

	auth := make([]byte, 0, len(verify)+len(authKey)+32+32+32+len(HsNtorProtoID)+6)
	auth = append(auth, verify...)
	auth = append(auth, authKey...)
	auth = append(auth, B.Bytes()...)
	auth = append(auth, Y.Bytes()...)
	auth = append(auth, X.Bytes()...)
	auth = append(auth, HsNtorProtoID...)
	auth = append(auth, "Server"...)
	authMac := hsMac(auth, hsMacProtoID)

	if subtle.ConstantTimeCompare(authMac, theirAuth) != 1 {
		return nil, errors.New("hs-ntor: rendezvous AUTH mismatch")
	}
	return ntorKeySeed, nil
}

func aes256Ctr(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(out, data)
	return out, nil
}

// ParseECDHKeys interprets a raw X25519 public-key point as an ecdh.PublicKey.
// The descriptor intro onion key is exactly such a 32-byte point.
func ParseECDHKeys(raw []byte) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	if len(raw) != 32 {
		return nil, nil, fmt.Errorf("hs/crypto: bad x25519 point length %d", len(raw))
	}
	B, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, B, nil
}
