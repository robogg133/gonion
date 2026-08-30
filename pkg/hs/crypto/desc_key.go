package crypto

import (
	"crypto/hmac"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
)

var errNilBlindPk = errors.New("hs/crypto: nil blinded public key")

// CircuitKeys is the end-to-end relay key set (matches gonion's crypto import so
// E2EKeys can hand keys straight to Circuit.AppendE2EHop). Df/Db are the
// SHA-1 digest seeds, Kf/Kb the AES-128-CTR keys.
type CircuitKeys struct {
	Df []byte
	Db []byte
	Kf []byte
	Kb []byte
}

// E2EKeys derives the hidden-service end-to-end relay keys from the ntor key
// seed produced by HsClientFinishRendezvous (rend-spec-v3 §3.3.2):
//
//	K = SHAKE256(ntor_seed || (":hs_key_expand" || subcredential), 72)
//	Df = K[0:20]; Db = K[20:40]; Kf = K[40:56]; Kb = K[56:72]
//
// The 72-byte layout matches crypto.CircuitKeys so the result feeds straight
// into gonion.Circuit.AppendE2EHop.
func E2EKeys(ntorSeed, subcred []byte) (CircuitKeys, error) {
	if len(ntorSeed) != HsNtorKeySeedLen {
		return CircuitKeys{}, errors.New("hs/crypto: bad ntor seed length")
	}
	info := make([]byte, 0, len(mHsexpand)+len(subcred))
	info = append(info, mHsexpand...)
	info = append(info, subcred...)
	raw := shsKDF(ntorSeed, info, 72)
	return CircuitKeys{
		Df: raw[0:20],
		Db: raw[20:40],
		Kf: raw[40:56],
		Kb: raw[56:72],
	}, nil
}

// EncryptDescriptor seals a descriptor plaintext with K_enc (AES-256-CTR,
// zero IV) and prepends a SHA3-256 HMAC (K_mac) of the ciphertext. The blob
// layout (MAC || ciphertext) matches rend-spec-v3 §2.4.
func EncryptDescriptor(k KdfKeys, plaintext []byte) ([]byte, error) {
	ct, err := aes256Ctr(k.KEnc, plaintext)
	if err != nil {
		return nil, err
	}
	mac := hmacSHA3(k.KMac, ct)
	out := make([]byte, 0, len(mac)+len(ct))
	out = append(out, mac...)
	out = append(out, ct...)
	return out, nil
}

// DecryptDescriptor verifies the HMAC and AES-256-CTR decrypts a descriptor
// blob (rend-spec-v3 §2.4). Returns the plaintext on success.
func DecryptDescriptor(k KdfKeys, blob []byte) ([]byte, error) {
	if len(blob) < HsDescKeyLen {
		return nil, errors.New("hs/crypto: descriptor blob shorter than MAC")
	}
	mac := blob[:HsDescKeyLen]
	ct := blob[HsDescKeyLen:]
	if subtle.ConstantTimeCompare(mac, hmacSHA3(k.KMac, ct)) != 1 {
		return nil, errors.New("hs/crypto: descriptor MAC mismatch")
	}
	return aes256Ctr(k.KEnc, ct)
}

func hmacSHA3(key, data []byte) []byte {
	h := macSHA3(key)
	h.Write(data)
	return h.Sum(nil)
}

func macSHA3(key []byte) hash.Hash {
	return hmac.New(func() hash.Hash { return sha3.New256() }, key)
}

// rend-spec-v3 §HSDESC-KEYS / §DESC-FETCH. The client only knows the blinded
// public key, from which the descriptor encryption keys (K_enc/K_mac/K_id) and
// the per-replica descriptor id are derived.

const (
	// descCertifyLabel seeds KEY_SEED (rend-spec-v3 §2.3.2 / §2.4).
	descCertifyLabel = "tor-hs-desc-encryption-key-certify"
	// descKeyExpandLabel expands KEY_SEED into K_enc||K_mac||K_id.
	descKeyExpandLabel = "tor-hs-descriptor-encryption-keys"
	// descReqLabel seeds the descriptor-id (rend-spec-v3 §2.3.1).
	descReqLabel = "tor-hs-directory-hs-desc-request"

	// HsDescKeyLen is the length of each derived descriptor key (AES-256 / SHA3-256).
	HsDescKeyLen = 32
)

// KdfKeys holds the descriptor symmetric keys derived from the blinded key.
type KdfKeys struct {
	KEnc []byte // 32 bytes, AES-256-CTR key
	KMac []byte // 32 bytes, HMAC-SHA3-256 key
	KId  []byte // 32 bytes, descriptor id seed
}

// DescKeys derives (K_enc, K_mac, K_id) from the blinded public key following
// rend-spec-v3 §HSDESC-KEYS:
//
//	KEY_SEED = SHA3-256("tor-hs-desc-encryption-key-certify" || blindPk)
//	K        = SHAKE256(KEY_SEED || "tor-hs-descriptor-encryption-keys", 96)
//	K_enc = K[0:32]; K_mac = K[32:64]; K_id = K[64:96]
func DescKeys(blindPk *BlindedPublicKey) (KdfKeys, error) {
	if blindPk == nil || len(blindPk.blindPk) == 0 {
		return KdfKeys{}, errNilBlindPk
	}

	seed := sha3.New256()
	seed.Write([]byte(descCertifyLabel))
	seed.Write(blindPk.blindPk)
	keySeed := seed.Sum(nil)

	raw := shsKDF(keySeed, []byte(descKeyExpandLabel), HsDescKeyLen*3)
	return KdfKeys{
		KEnc: raw[0:HsDescKeyLen],
		KMac: raw[HsDescKeyLen : 2*HsDescKeyLen],
		KId:  raw[2*HsDescKeyLen : 3*HsDescKeyLen],
	}, nil
}

// DescriptorID computes the v3 descriptor fetch id for a (period, replica):
//
//	H("tor-hs-directory-hs-desc-request" || blindPk ||
//	  INT_8(periodLen) || INT_8(periodNum) || INT_8(replica))
//
// (rend-spec-v3 §2.3.1). INT_8 is an 8-byte big-endian integer.
func DescriptorID(blindPk *BlindedPublicKey, periodNum, periodLen, replica uint64) [32]byte {
	h := sha3.New256()
	h.Write([]byte(descReqLabel))
	h.Write(blindPk.blindPk)

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], periodLen)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], periodNum)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], replica)
	h.Write(b[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
