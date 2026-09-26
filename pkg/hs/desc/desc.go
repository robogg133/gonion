// Package desc encodes, authenticates and decrypts Tor onion-service v3
// descriptors. It does not accept Gonion's former private descriptor format.
package desc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/lspec"
)

type IntroPoint struct {
	// OnionKey is the relay's ntor onion key, used to extend to the relay.
	OnionKey []byte
	// EncKey is KP_hss_ntor, the service's key for HS-ntor introduction encryption.
	EncKey    []byte
	AuthKey   []byte
	LinkSpecs []lspec.Lspec
	// LinkSpecifiers is the complete NSPEC-prefixed wire block, including unknown
	// types and original ordering. Forward this verbatim in EXTEND2.
	LinkSpecifiers     []byte
	AuthKeyCertificate []byte
	EncKeyCertificate  []byte
	CertificateExpiry  time.Time
}

type Descriptor struct {
	Version               int
	LifetimeSeconds       int
	RevisionCounter       uint64
	BlindedKey            ed25519.PublicKey
	SigningKey            ed25519.PublicKey
	SigningKeyCertificate []byte
	CertificateExpiry     time.Time
	Subcredential         []byte
	IntroPoints           []IntroPoint
	// SuperencryptedRaw is the authenticated ciphertext from the outer wrapper.
	SuperencryptedRaw  []byte
	Create2Formats     []uint16
	IntroAuthRequired  []string
	SingleOnionService bool
}

// Parse verifies a signed outer wrapper using its embedded blinded key. It does
// NOT establish which onion service owns that key or decrypt introduction
// points. Clients must use Decode with the expected blinded public key instead.
func Parse(body []byte) (*Descriptor, error) { return parseOuter(body, nil, time.Now()) }

func parseOuter(body, expected []byte, now time.Time) (*Descriptor, error) {
	tokens, err := tokenize(body)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 || tokens[0].name != "hs-descriptor" || tokens[0].offset != 0 || tokens[len(tokens)-1].name != "signature" {
		return nil, errors.New("hs/desc: invalid outer wrapper boundaries")
	}
	version, err := one(tokens, "hs-descriptor", 1, "")
	if err != nil {
		return nil, err
	}
	v, err := uintField(version.args[0], 32)
	if err != nil || v != 3 {
		return nil, errors.New("hs/desc: unsupported descriptor version")
	}
	lifetime, err := one(tokens, "descriptor-lifetime", 1, "")
	if err != nil {
		return nil, err
	}
	minutes, err := uintField(lifetime.args[0], 32)
	if err != nil || minutes < 30 || minutes > 720 {
		return nil, errors.New("hs/desc: invalid descriptor lifetime")
	}
	cert, err := one(tokens, "descriptor-signing-key-cert", 0, "ED25519 CERT")
	if err != nil {
		return nil, err
	}
	c, err := parseCertificate(cert.object, 8, expected, now)
	if err != nil {
		return nil, err
	}
	revision, err := one(tokens, "revision-counter", 1, "")
	if err != nil {
		return nil, err
	}
	r, err := uintField(revision.args[0], 64)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: invalid revision: %w", err)
	}
	encrypted, err := one(tokens, "superencrypted", 0, "MESSAGE")
	if err != nil {
		return nil, err
	}
	if len(encrypted.object) <= 48 {
		return nil, errors.New("hs/desc: truncated superencrypted layer")
	}
	sig, err := one(tokens, "signature", 1, "")
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(body[sig.offset:], []byte("signature ")) {
		return nil, errors.New("hs/desc: malformed descriptor signature line")
	}
	signature, err := decodeSize(sig.args[0], 64)
	if err != nil {
		return nil, err
	}
	// Tor signs through the newline preceding 'signature', not the signature line.
	signed := append([]byte(signaturePrefix), body[:sig.offset]...)
	if !ed25519.Verify(c.key, signed, signature) {
		return nil, errors.New("hs/desc: invalid descriptor signature")
	}
	// No unsigned non-whitespace content is permitted after the signature.
	if !bytes.Equal(bytes.TrimSpace(body[sig.offset:]), []byte("signature "+sig.args[0])) {
		return nil, errors.New("hs/desc: invalid signature line")
	}
	return &Descriptor{Version: 3, LifetimeSeconds: int(minutes) * 60, RevisionCounter: r, BlindedKey: c.signer, SigningKey: c.key, SigningKeyCertificate: cert.object, CertificateExpiry: c.expires, SuperencryptedRaw: encrypted.object}, nil
}

// Decode validates the expected identity, both signatures and encryption layers,
// and every introduction certificate before returning a descriptor. clientAuth
// is nil for a public service, or the client's X25519 private key. now is the
// certificate-validation time; period selection must use consensus valid-after.
// Callers caching descriptors must reject revisions lower than their cached
// RevisionCounter for the same BlindedKey; Decode has no mutable replay cache.
func Decode(body []byte, blinded *crypto.BlindedPublicKey, clientAuth *ecdh.PrivateKey, now time.Time) (*Descriptor, error) {
	sub, err := deriveSubcredential(blinded)
	if err != nil {
		return nil, err
	}
	d, err := parseOuter(body, blinded.Bytes(), now)
	if err != nil {
		return nil, err
	}
	middle, err := crypto.DecryptDescriptor(d.BlindedKey, sub, d.RevisionCounter, crypto.SuperencryptedLayer, d.SuperencryptedRaw)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: outer layer: %w", err)
	}
	defer clear(middle)
	middle, err = unpad(middle)
	if err != nil {
		return nil, err
	}
	inner, err := decryptMiddle(middle, d.BlindedKey, sub, d.RevisionCounter, clientAuth)
	if err != nil {
		return nil, err
	}
	defer clear(inner)
	inner, err = unpad(inner)
	if err != nil {
		return nil, err
	}
	if err = parseInner(d, inner, now); err != nil {
		return nil, err
	}
	d.Subcredential = sub
	return d, nil
}

func unpad(raw []byte) ([]byte, error) {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		for _, b := range raw[i:] {
			if b != 0 {
				return nil, errors.New("hs/desc: nonzero data after NUL padding")
			}
		}
		return raw[:i], nil
	}
	return raw, nil
}

func deriveSubcredential(blinded *crypto.BlindedPublicKey) (crypto.SubCredential, error) {
	if blinded == nil {
		return nil, errors.New("hs/desc: missing blinded public key")
	}
	cred, err := crypto.GenerateCredential(blinded.Pk())
	if err != nil {
		return nil, err
	}
	return crypto.GenerateSubCredential(cred, blinded.Bytes())
}

func parseInner(d *Descriptor, body []byte, now time.Time) error {
	tokens, err := tokenize(body)
	if err != nil {
		return err
	}
	split := len(tokens)
	for i, t := range tokens {
		if t.name == "introduction-point" {
			split = i
			break
		}
	}
	header := tokens[:split]
	formats, err := oneVariable(header, "create2-formats")
	if err != nil {
		return err
	}
	ntor := false
	for _, s := range formats.args {
		n, err := uintField(s, 16)
		if err != nil {
			return errors.New("hs/desc: invalid CREATE2 format")
		}
		d.Create2Formats = append(d.Create2Formats, uint16(n))
		ntor = ntor || n == 2
	}
	if !ntor {
		return errors.New("hs/desc: descriptor does not support ntor")
	}
	for _, t := range header {
		switch t.name {
		case "intro-auth-required":
			if d.IntroAuthRequired != nil || len(t.args) == 0 || t.armor != "" {
				return errors.New("hs/desc: invalid intro-auth-required")
			}
			d.IntroAuthRequired = append([]string(nil), t.args...)
		case "single-onion-service":
			if d.SingleOnionService || len(t.args) != 0 || t.armor != "" {
				return errors.New("hs/desc: invalid single-onion-service")
			}
			d.SingleOnionService = true
		}
	}
	for split < len(tokens) {
		end := split + 1
		for end < len(tokens) && tokens[end].name != "introduction-point" {
			end++
		}
		if len(d.IntroPoints) >= 20 {
			return errors.New("hs/desc: more than 20 introduction points")
		}
		ip, err := parseIntro(tokens[split:end], d.SigningKey, now)
		if err != nil {
			return err
		}
		if ip.CertificateExpiry.Before(d.CertificateExpiry) {
			d.CertificateExpiry = ip.CertificateExpiry
		}
		d.IntroPoints = append(d.IntroPoints, ip)
		split = end
	}
	return nil
}
func oneVariable(tokens []token, name string) (token, error) {
	var found *token
	for i := range tokens {
		t := &tokens[i]
		if t.name != name {
			continue
		}
		if found != nil || len(t.args) == 0 || t.armor != "" {
			return token{}, fmt.Errorf("hs/desc: invalid %s", name)
		}
		found = t
	}
	if found == nil {
		return token{}, fmt.Errorf("hs/desc: missing %s", name)
	}
	return *found, nil
}

func ntorKey(tokens []token, name string) ([]byte, error) {
	var result []byte
	for _, t := range tokens {
		if t.name != name {
			continue
		}
		if len(t.args) < 2 {
			return nil, fmt.Errorf("hs/desc: invalid %s", name)
		}
		if t.args[0] != "ntor" {
			continue
		}
		if result != nil || t.armor != "" {
			return nil, fmt.Errorf("hs/desc: duplicate %s ntor", name)
		}
		var err error
		result, err = decodeSize(t.args[1], 32)
		if err != nil {
			return nil, err
		}
		if err = validateX25519(result); err != nil {
			return nil, err
		}
	}
	if result == nil {
		return nil, fmt.Errorf("hs/desc: missing %s ntor", name)
	}
	return result, nil
}
func parseIntro(tokens []token, signing ed25519.PublicKey, now time.Time) (IntroPoint, error) {
	var ip IntroPoint
	t, err := one(tokens, "introduction-point", 1, "")
	if err != nil {
		return ip, err
	}
	ip.LinkSpecifiers, err = base64Decode(t.args[0])
	if err != nil {
		return ip, err
	}
	ip.LinkSpecs, err = decodeLinkSpecs(ip.LinkSpecifiers)
	if err != nil {
		return ip, err
	}
	ip.OnionKey, err = ntorKey(tokens, "onion-key")
	if err != nil {
		return ip, err
	}
	ip.EncKey, err = ntorKey(tokens, "enc-key")
	if err != nil {
		return ip, err
	}
	auth, err := one(tokens, "auth-key", 0, "ED25519 CERT")
	if err != nil {
		return ip, err
	}
	ac, err := parseCertificate(auth.object, 9, signing, now)
	if err != nil {
		return ip, err
	}
	enc, err := one(tokens, "enc-key-cert", 0, "ED25519 CERT")
	if err != nil {
		return ip, err
	}
	ec, err := parseCertificate(enc.object, 11, signing, now)
	if err != nil {
		return ip, err
	}
	expected, err := encryptionCertKey(ip.EncKey)
	if err != nil {
		return ip, err
	}
	if !bytes.Equal(ec.key, expected) {
		return ip, errors.New("hs/desc: encryption certificate key mismatch")
	}
	// Obsolete RSA introduction points are not usable by this v3-only client.
	for _, t := range tokens {
		if t.name == "legacy-key" || t.name == "legacy-key-cert" {
			return ip, errors.New("hs/desc: obsolete legacy introduction key")
		}
	}
	ip.CertificateExpiry = ac.expires
	if ec.expires.Before(ip.CertificateExpiry) {
		ip.CertificateExpiry = ec.expires
	}
	ip.AuthKey = ac.key
	ip.AuthKeyCertificate = auth.object
	ip.EncKeyCertificate = enc.object
	return ip, nil
}

// Fetch retrieves a descriptor over BEGIN_DIR on a dedicated circuit already
// extended to hsdir. The caller owns path selection and circuit disposal.
// period/replica parameters are retained for existing callers; the fetch path
// uses only the raw base64 blinded public key, never a hash-ring index.
func Fetch(ctx context.Context, circ capi.Circ, hsdir common.RouterStatus, blinded *crypto.BlindedPublicKey, periodNum, periodLen, replica uint64) (*Descriptor, error) {
	return FetchAuthorized(ctx, circ, hsdir, blinded, nil)
}

// FetchAuthorized is Fetch with optional descriptor client authorization.
func FetchAuthorized(ctx context.Context, circ capi.Circ, hsdir common.RouterStatus, blinded *crypto.BlindedPublicKey, clientAuth *ecdh.PrivateKey) (*Descriptor, error) {
	if _, err := deriveSubcredential(blinded); err != nil {
		return nil, err
	}
	path := "/tor/hs/3/" + base64.RawStdEncoding.EncodeToString(blinded.Bytes())
	raw, err := directoryRequest(ctx, circ, hsdir, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	return Decode(raw, blinded, clientAuth, time.Now())
}

// Publish uses a dedicated anonymous BEGIN_DIR circuit, never the public
// directory port. The caller owns disposal of the circuit and revision state.
func Publish(ctx context.Context, circ capi.Circ, hsdir common.RouterStatus, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxDescriptorSize {
		return errors.New("hs/desc: invalid publication size")
	}
	if _, err := Parse(raw); err != nil {
		return err
	}
	_, err := directoryRequest(ctx, circ, hsdir, http.MethodPost, "/tor/hs/3/publish", raw)
	return err
}

func directoryRequest(ctx context.Context, circ capi.Circ, hsdir common.RouterStatus, method, path string, body []byte) ([]byte, error) {
	if !hsdir.StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] || !hsdir.ProtoVersions.HSDir.CheckIsTrue(common.VERSION_2) {
		return nil, errors.New("hs/desc: selected relay does not advertise HSDir=2")
	}
	if circ == nil || circ.HopCount() < 3 {
		return nil, errors.New("hs/desc: a dedicated anonymous HSDir circuit is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Also interrupts NewStream, which has no context argument. This circuit must
	// not be shared, as required by rend-spec-v3 section 2.2.6.
	stop := context.AfterFunc(ctx, func() { circ.Close() })
	defer stop()
	stream, err := circ.NewStream("dir", circ.HopCount()-1)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: BEGIN_DIR: %w", err)
	}
	defer stream.Free()
	req, err := http.NewRequestWithContext(ctx, method, "http://hsdir"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Close = true
	req.Header.Set("Accept-Encoding", "identity")
	req.Header["User-Agent"] = nil
	conn := stream.Conn()
	if conn == nil {
		return nil, errors.New("hs/desc: missing directory stream connection")
	}
	if err = req.Write(conn); err != nil {
		return nil, fmt.Errorf("hs/desc: write request: %w", err)
	}
	// ReadResponse has no configurable header limit: cap the entire wire input,
	// then enforce separate header and decoded-body limits.
	limited := &io.LimitedReader{R: conn, N: MaxDescriptorSize + 16384}
	reader := bufio.NewReader(limited)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: HTTP response: %w", err)
	}
	defer resp.Body.Close()
	if MaxDescriptorSize+16384-limited.N-int64(reader.Buffered()) > 16384 {
		return nil, errors.New("hs/desc: HTTP headers too large")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hs/desc: HSDir returned %d", resp.StatusCode)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil, errors.New("hs/desc: unexpected HTTP content encoding")
	}
	if resp.ContentLength > MaxDescriptorSize {
		return nil, errors.New("hs/desc: HTTP body too large")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDescriptorSize+1))
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if len(raw) > MaxDescriptorSize {
		return nil, errors.New("hs/desc: HTTP body too large")
	}
	return raw, nil
}
