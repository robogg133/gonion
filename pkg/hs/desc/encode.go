package desc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
)

// EncodeOptions describes a public or client-authorized v3 descriptor.
// Keep RevisionCounter monotonically increasing for each blinded key; callers
// must persist it. Zero is a valid initial revision, not an automatic timestamp.
type EncodeOptions struct {
	BlindedKey         *hscrypto.BlindedPrivateKey
	SigningKey         ed25519.PrivateKey
	RevisionCounter    uint64
	LifetimeMinutes    int // Zero defaults to Tor's 180 minutes.
	CertificateExpiry  time.Time
	IntroPoints        []IntroPoint
	AuthorizedClients  []*ecdh.PublicKey // Empty means public access.
	SingleOnionService bool
	// For offline signing, supply these instead of BlindedKey. SigningCertificate
	// returns the binary certificate, and the blinded public key retains the
	// service identity needed to derive the subcredential.
	BlindedPublicKey      *hscrypto.BlindedPublicKey
	SigningKeyCertificate []byte
}

// Encode signs the wrapper and introduction certificates and encrypts both
// layers. IntroPoints require distinct OnionKey/EncKey roles, AuthKey, and link
// specifiers. It generates fresh salts, an ephemeral authorization key, and fake
// authorization records padded to a multiple of 16 even for public services.
func Encode(o EncodeOptions) ([]byte, error) {
	if err := validatePrivateKey(o.SigningKey); err != nil {
		return nil, err
	}
	if len(o.IntroPoints) > 20 || len(o.AuthorizedClients) > 512 {
		return nil, errors.New("hs/desc: too many introduction points or authorized clients")
	}
	if o.LifetimeMinutes == 0 {
		o.LifetimeMinutes = 180
	}
	if o.LifetimeMinutes < 30 || o.LifetimeMinutes > 720 {
		return nil, errors.New("hs/desc: invalid descriptor lifetime")
	}
	now := time.Now()
	if !o.CertificateExpiry.After(now) {
		return nil, errors.New("hs/desc: certificate expiration must be in the future")
	}
	blinded := o.BlindedPublicKey
	cert := o.SigningKeyCertificate
	if o.BlindedKey != nil {
		if blinded != nil || len(cert) != 0 {
			return nil, errors.New("hs/desc: choose online or offline blinded signing, not both")
		}
		blinded = o.BlindedKey.PublicKey()
		var err error
		cert, err = SigningCertificate(o.BlindedKey, ed25519.PublicKey(o.SigningKey[32:]), o.CertificateExpiry)
		if err != nil {
			return nil, err
		}
	}
	sub, err := deriveSubcredential(blinded)
	if err != nil {
		return nil, err
	}
	outerCert, err := parseCertificate(cert, 8, blinded.Bytes(), now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(outerCert.key, o.SigningKey[32:]) {
		return nil, errors.New("hs/desc: signing private key does not match certificate")
	}
	var inner strings.Builder
	inner.WriteString("create2-formats 2\n")
	if o.SingleOnionService {
		inner.WriteString("single-onion-service\n")
	}
	for _, ip := range o.IntroPoints {
		raw, err := encodeLinkSpecs(ip)
		if err != nil {
			return nil, err
		}
		if err = validateX25519(ip.OnionKey); err != nil {
			return nil, err
		}
		encCertKey, err := encryptionCertKey(ip.EncKey)
		if err != nil {
			return nil, err
		}
		auth, err := signCertificate(9, ip.AuthKey, o.SigningKey, o.CertificateExpiry)
		if err != nil {
			return nil, err
		}
		enc, err := signCertificate(11, encCertKey, o.SigningKey, o.CertificateExpiry)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&inner, "introduction-point %s\nonion-key ntor %s\nauth-key\n%s\nenc-key ntor %s\nenc-key-cert\n%s\n",
			base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(ip.OnionKey), armor("ED25519 CERT", auth), base64.StdEncoding.EncodeToString(ip.EncKey), armor("ED25519 CERT", enc))
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var cookie []byte
	if len(o.AuthorizedClients) > 0 {
		cookie, err = hashedRandom(hscrypto.DescriptorCookieLen)
		if err != nil {
			return nil, err
		}
		defer clear(cookie)
	}
	secret := append(blinded.Bytes(), cookie...)
	defer clear(secret)
	encrypted, err := hscrypto.EncryptDescriptor(secret, sub, o.RevisionCounter, hscrypto.EncryptedLayer, []byte(inner.String()))
	if err != nil {
		return nil, err
	}
	clients := make([]authClient, 0, ((len(o.AuthorizedClients)+15)/16)*16)
	seen := make(map[string]bool)
	for _, pub := range o.AuthorizedClients {
		if pub == nil || pub.Curve() != ecdh.X25519() || seen[string(pub.Bytes())] {
			return nil, errors.New("hs/desc: invalid or duplicate authorized client")
		}
		seen[string(pub.Bytes())] = true
		iv, err := hashedRandom(16)
		if err != nil {
			return nil, err
		}
		c, err := buildAuthClient(sub, ephemeral, pub, cookie, iv)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	for len(clients) == 0 || len(clients)%16 != 0 {
		b, err := hashedRandom(40)
		if err != nil {
			return nil, err
		}
		clients = append(clients, authClient{id: b[:8], iv: b[8:24], cookie: b[24:]})
	}
	// Like C Tor, shuffle to hide which records are real and their config order.
	for i := len(clients) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		clients[i], clients[j.Int64()] = clients[j.Int64()], clients[i]
	}
	var middle strings.Builder
	fmt.Fprintf(&middle, "desc-auth-type x25519\ndesc-auth-ephemeral-key %s\n", base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()))
	for _, c := range clients {
		fmt.Fprintf(&middle, "auth-client %s %s %s\n", base64.StdEncoding.EncodeToString(c.id), base64.StdEncoding.EncodeToString(c.iv), base64.StdEncoding.EncodeToString(c.cookie))
	}
	fmt.Fprintf(&middle, "encrypted\n%s", armor("MESSAGE", encrypted))
	if middle.Len() > MaxDescriptorSize-48 {
		return nil, errors.New("hs/desc: descriptor middle layer too large")
	}
	padded := make([]byte, ((middle.Len()+9999)/10000)*10000)
	copy(padded, middle.String())
	superencrypted, err := hscrypto.EncryptDescriptor(blinded.Bytes(), sub, o.RevisionCounter, hscrypto.SuperencryptedLayer, padded)
	if err != nil {
		return nil, err
	}
	outer := fmt.Sprintf("hs-descriptor 3\ndescriptor-lifetime %d\ndescriptor-signing-key-cert\n%s\nrevision-counter %d\nsuperencrypted\n%s\n", o.LifetimeMinutes, armor("ED25519 CERT", cert), o.RevisionCounter, armor("MESSAGE", superencrypted))
	sig := ed25519.Sign(o.SigningKey, append([]byte(signaturePrefix), []byte(outer)...))
	raw := []byte(outer + "signature " + base64.RawStdEncoding.EncodeToString(sig) + "\n")
	if len(raw) > MaxDescriptorSize {
		return nil, errors.New("hs/desc: encoded descriptor exceeds size limit")
	}
	return raw, nil
}

func hashedRandom(n int) ([]byte, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	h := sha3.NewSHAKE256()
	h.Write(seed[:])
	out := make([]byte, n)
	h.Read(out)
	return out, nil
}

type authClient struct{ id, iv, cookie []byte }

func cookieKeys(sub []byte, private *ecdh.PrivateKey, public *ecdh.PublicKey) ([]byte, error) {
	if len(sub) != 32 || private == nil || public == nil || private.Curve() != ecdh.X25519() || public.Curve() != ecdh.X25519() {
		return nil, errors.New("hs/desc: invalid authorization key")
	}
	secret, err := private.ECDH(public)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: authorization ECDH: %w", err)
	}
	defer clear(secret)
	h := sha3.NewSHAKE256()
	h.Write(sub)
	h.Write(secret)
	out := make([]byte, 40)
	h.Read(out)
	return out, nil
}
func cookieCrypt(key, iv, input []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) != 16 || len(input) != hscrypto.DescriptorCookieLen {
		return nil, errors.New("hs/desc: invalid cookie cipher input")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(input))
	cipher.NewCTR(block, iv).XORKeyStream(out, input)
	return out, nil
}
func buildAuthClient(sub []byte, private *ecdh.PrivateKey, public *ecdh.PublicKey, cookie, iv []byte) (authClient, error) {
	keys, err := cookieKeys(sub, private, public)
	if err != nil {
		return authClient{}, err
	}
	defer clear(keys)
	encrypted, err := cookieCrypt(keys[8:], iv, cookie)
	if err != nil {
		return authClient{}, err
	}
	return authClient{id: append([]byte(nil), keys[:8]...), iv: append([]byte(nil), iv...), cookie: encrypted}, nil
}

// ErrClientAuthorization indicates that the inner layer could not be opened
// without valid client credentials. No unauthenticated plaintext is returned.
var ErrClientAuthorization = errors.New("hs/desc: descriptor requires valid client authorization")

func decryptMiddle(body, blinded, sub []byte, revision uint64, clientAuth *ecdh.PrivateKey) ([]byte, error) {
	tokens, err := tokenize(body)
	if err != nil {
		return nil, err
	}
	typ, err := one(tokens, "desc-auth-type", 1, "")
	if err != nil {
		return nil, err
	}
	if typ.args[0] != "x25519" {
		return nil, errors.New("hs/desc: unsupported descriptor authorization type")
	}
	eph, err := one(tokens, "desc-auth-ephemeral-key", 1, "")
	if err != nil {
		return nil, err
	}
	raw, err := decodeSize(eph.args[0], 32)
	if err != nil {
		return nil, err
	}
	if err = validateX25519(raw); err != nil {
		return nil, err
	}
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	var clients []authClient
	for _, t := range tokens {
		if t.name != "auth-client" {
			continue
		}
		if len(t.args) != 3 || t.armor != "" {
			return nil, errors.New("hs/desc: invalid auth-client record")
		}
		id, err := decodeSize(t.args[0], 8)
		if err != nil {
			return nil, err
		}
		iv, err := decodeSize(t.args[1], 16)
		if err != nil {
			return nil, err
		}
		cookie, err := decodeSize(t.args[2], hscrypto.DescriptorCookieLen)
		if err != nil {
			return nil, err
		}
		clients = append(clients, authClient{id: id, iv: iv, cookie: cookie})
	}
	if len(clients) == 0 {
		return nil, errors.New("hs/desc: missing auth-client records")
	}
	encrypted, err := one(tokens, "encrypted", 0, "MESSAGE")
	if err != nil {
		return nil, err
	}
	// Authorization is deliberately not signalled. Try public-service decryption
	// first, as C Tor does, even if a client authorization key was configured.
	plaintext, err := hscrypto.DecryptDescriptor(blinded, sub, revision, hscrypto.EncryptedLayer, encrypted.object)
	if err == nil {
		return plaintext, nil
	}
	if clientAuth == nil {
		return nil, ErrClientAuthorization
	}
	keys, err := cookieKeys(sub, clientAuth, public)
	if err != nil {
		return nil, err
	}
	defer clear(keys)
	for _, c := range clients {
		if subtle.ConstantTimeCompare(keys[:8], c.id) != 1 {
			continue
		}
		cookie, err := cookieCrypt(keys[8:], c.iv, c.cookie)
		if err != nil {
			return nil, err
		}
		secret := append(append([]byte(nil), blinded...), cookie...)
		clear(cookie)
		plaintext, err = hscrypto.DecryptDescriptor(secret, sub, revision, hscrypto.EncryptedLayer, encrypted.object)
		clear(secret)
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrClientAuthorization
}
