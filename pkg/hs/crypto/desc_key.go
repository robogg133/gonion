package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// CircuitKeys is the HS-v3 end-to-end relay key set. Df/Db seed SHA3-256
// digests; Kf/Kb are AES-256-CTR keys. All four values are 32 bytes.
type CircuitKeys struct {
	Df []byte
	Db []byte
	Kf []byte
	Kb []byte
}

// E2EKeys implements rend-spec-v3 section 4.2.1:
// SHAKE256(NTOR_KEY_SEED | PROTOID | ":hs_key_expand", 128).
// The second argument is retained for source compatibility and is ignored:
// the subcredential belongs to introduction key derivation, not this KDF.
func E2EKeys(ntorSeed, _ []byte) (CircuitKeys, error) {
	if len(ntorSeed) != HsNtorKeySeedLen {
		return CircuitKeys{}, errors.New("hs/crypto: bad ntor seed length")
	}
	raw := shsKDF(ntorSeed, hsExpandProto, 128)
	return CircuitKeys{Df: raw[0:32], Db: raw[32:64], Kf: raw[64:96], Kb: raw[96:128]}, nil
}

// DescriptorLayer selects the domain separator in rend-spec-v3 section 2.5.3.
type DescriptorLayer string

const (
	SuperencryptedLayer DescriptorLayer = "hsdir-superencrypted-data"
	EncryptedLayer      DescriptorLayer = "hsdir-encrypted-data"
	MaxDescriptorSize                   = 50000
	DescriptorCookieLen                 = 16 // C Tor's HS_DESC_DESCRIPTOR_COOKIE_LEN.
)

func descriptorKeys(secretData, subcredential []byte, revision uint64, salt []byte, layer DescriptorLayer) ([]byte, error) {
	if len(subcredential) != 32 || len(salt) != 16 ||
		(layer != SuperencryptedLayer && layer != EncryptedLayer) ||
		(len(secretData) != 32 && !(layer == EncryptedLayer && len(secretData) == 32+DescriptorCookieLen)) {
		return nil, errors.New("hs/crypto: invalid descriptor KDF input")
	}
	if err := ValidateEd25519PublicKey(secretData[:32]); err != nil {
		return nil, err
	}
	h := sha3.NewSHAKE256()
	h.Write(secretData)
	h.Write(subcredential)
	h.Write(binary.BigEndian.AppendUint64(nil, revision))
	h.Write(salt)
	h.Write([]byte(layer))
	keys := make([]byte, 80)
	h.Read(keys)
	return keys, nil
}

func descriptorMAC(key, salt, ciphertext []byte) []byte {
	h := sha3.New256()
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(key))))
	h.Write(key)
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(salt))))
	h.Write(salt)
	h.Write(ciphertext)
	return h.Sum(nil)
}

// EncryptDescriptor encrypts one descriptor layer as SALT | ciphertext | MAC.
// The caller supplies padding for the outer layer. A fresh hashed salt is used.
func EncryptDescriptor(secretData, subcredential []byte, revision uint64, layer DescriptorLayer, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxDescriptorSize-48 {
		return nil, errors.New("hs/crypto: invalid descriptor plaintext length")
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}
	salt := sha3.Sum256(entropy[:])
	return encryptDescriptorSalt(secretData, subcredential, revision, layer, plaintext, salt[:16])
}

func encryptDescriptorSalt(secretData, subcredential []byte, revision uint64, layer DescriptorLayer, plaintext, salt []byte) ([]byte, error) {
	keys, err := descriptorKeys(secretData, subcredential, revision, salt, layer)
	if err != nil {
		return nil, err
	}
	defer clear(keys)
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16+len(plaintext), 48+len(plaintext))
	copy(out, salt)
	cipher.NewCTR(block, keys[32:48]).XORKeyStream(out[16:], plaintext)
	return append(out, descriptorMAC(keys[48:], salt, out[16:])...), nil
}

// DecryptDescriptor authenticates a layer before releasing any plaintext.
func DecryptDescriptor(secretData, subcredential []byte, revision uint64, layer DescriptorLayer, blob []byte) ([]byte, error) {
	if len(blob) <= 48 || len(blob) > MaxDescriptorSize {
		return nil, errors.New("hs/crypto: invalid descriptor ciphertext length")
	}
	salt, ciphertext, mac := blob[:16], blob[16:len(blob)-32], blob[len(blob)-32:]
	keys, err := descriptorKeys(secretData, subcredential, revision, salt, layer)
	if err != nil {
		return nil, err
	}
	defer clear(keys)
	if subtle.ConstantTimeCompare(mac, descriptorMAC(keys[48:], salt, ciphertext)) != 1 {
		return nil, errors.New("hs/crypto: descriptor MAC mismatch")
	}
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, keys[32:48]).XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
