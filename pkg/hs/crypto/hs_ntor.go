package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
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

func hsMac(key, data []byte) []byte {
	h := hmac.New(sha3.New256, key)
	h.Write(data)
	return h.Sum(nil)
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
// intro auth key, subcred the service subcredential.
func HsClientIntro(privX *ecdh.PrivateKey, B *ecdh.PublicKey, authKey, subcred, plaintext []byte) (*HsClientKeys, []byte, error) {
	X := privX.PublicKey()
	expBx, err := privX.ECDH(B)

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

	macBody := make([]byte, 0, len(authKey)+32+32+len(encData))
	macBody = append(macBody, authKey...)
	macBody = append(macBody, B.Bytes()...)
	macBody = append(macBody, X.Bytes()...)
	macBody = append(macBody, encData...)
	mac := hsMac(macKey, macBody)

	out := make([]byte, 0, 32+len(encData)+HsNtorMacLen)
	out = append(out, X.Bytes()...)
	out = append(out, encData...)
	out = append(out, mac...)

	return &HsClientKeys{ENCKey: encKey, MACKey: macKey}, out, nil
}

// HsServiceIntro decrypts a client's intro payload and returns the plaintext
// plus the client public key X. b is the intro point secret key.
func HsServiceIntro(b *ecdh.PrivateKey, authKey, subcred, blob []byte) (*ecdh.PublicKey, []byte, error) {
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

	macBody := make([]byte, 0, len(authKey)+32+32+len(encData))
	macBody = append(macBody, authKey...)
	macBody = append(macBody, B.Bytes()...)
	macBody = append(macBody, X.Bytes()...)
	macBody = append(macBody, encData...)
	if subtle.ConstantTimeCompare(hsMac(macKey, macBody), theirMac) != 1 {
		return nil, nil, errors.New("hs-ntor: intro MAC mismatch")
	}

	plain, err := aes256Ctr(encKey, encData)
	if err != nil {
		return nil, nil, err
	}
	return X, plain, nil
}

// HsServiceRendezvousReply derives the service's rendezvous reply (SERVER_PK +
// AUTH). y is the service's single-use keypair.
func HsServiceRendezvousReply(X, B *ecdh.PublicKey, authKey []byte, serviceSK *ecdh.PrivateKey, y *ecdh.PrivateKey) ([]byte, error) {
	expXy, err := y.ECDH(X)
	if err != nil {
		return nil, err
	}
	expXb, err := serviceSK.ECDH(X)
	if err != nil {
		return nil, err
	}

	rend := make([]byte, 0, 32+32+len(authKey)+32+32+32+len(HsNtorProtoID))
	rend = append(rend, expXy...)
	rend = append(rend, expXb...)
	rend = append(rend, authKey...)
	rend = append(rend, B.Bytes()...)
	rend = append(rend, X.Bytes()...)
	rend = append(rend, y.PublicKey().Bytes()...)
	rend = append(rend, HsNtorProtoID...)

	verify := hsMac(hsVerifyProto, rend)

	auth := make([]byte, 0, len(verify)+len(authKey)+32+32+32+len(HsNtorProtoID)+6)
	auth = append(auth, verify...)
	auth = append(auth, authKey...)
	auth = append(auth, B.Bytes()...)
	auth = append(auth, y.PublicKey().Bytes()...)
	auth = append(auth, X.Bytes()...)
	auth = append(auth, HsNtorProtoID...)
	auth = append(auth, "Server"...)
	authMac := hsMac(hsMacProtoID, auth)

	reply := make([]byte, 0, 32+HsNtorMacLen)
	reply = append(reply, y.PublicKey().Bytes()...)
	reply = append(reply, authMac...)

	return reply, nil
}

// HsClientFinishRendezvous validates the service reply and returns the shared
// ntor key seed on the client side.
func HsClientFinishRendezvous(privX *ecdh.PrivateKey, B *ecdh.PublicKey, authKey, reply []byte) ([]byte, error) {
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

	ntorKeySeed := hsMac(hsEncProtoID, rend)
	verify := hsMac(hsVerifyProto, rend)

	auth := make([]byte, 0, len(verify)+len(authKey)+32+32+32+len(HsNtorProtoID)+6)
	auth = append(auth, verify...)
	auth = append(auth, authKey...)
	auth = append(auth, B.Bytes()...)
	auth = append(auth, Y.Bytes()...)
	auth = append(auth, X.Bytes()...)
	auth = append(auth, HsNtorProtoID...)
	auth = append(auth, "Server"...)
	authMac := hsMac(hsMacProtoID, auth)

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
