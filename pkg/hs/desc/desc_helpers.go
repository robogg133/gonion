package desc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"filippo.io/edwards25519/field"
	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/lspec"
)

const MaxDescriptorSize = hscrypto.MaxDescriptorSize
const signaturePrefix = "Tor onion service descriptor sig v3"

type token struct {
	name   string
	args   []string
	object []byte
	armor  string
	offset int
}

// tokenize bounds the complete document before splitting, and never normalizes
// the signed bytes. Unknown fields and their objects remain skippable.
func tokenize(body []byte) ([]token, error) {
	if len(body) == 0 || len(body) > MaxDescriptorSize {
		return nil, errors.New("hs/desc: invalid document size")
	}
	for _, b := range body {
		if b != '\n' && b != '\t' && (b < 32 || b > 126) {
			return nil, errors.New("hs/desc: invalid document character")
		}
	}
	lines := strings.Split(string(body), "\n")
	var out []token
	offset := 0
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		pos := offset
		offset += len(line) + 1
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if strings.HasPrefix(line, "-----") {
			return nil, errors.New("hs/desc: unexpected object armor")
		}
		t := token{name: f[0], args: f[1:], offset: pos}
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "-----BEGIN ") {
			i++
			begin := lines[i]
			offset += len(begin) + 1
			if !strings.HasSuffix(begin, "-----") {
				return nil, errors.New("hs/desc: invalid object armor")
			}
			t.armor = strings.TrimSuffix(strings.TrimPrefix(begin, "-----BEGIN "), "-----")
			end := "-----END " + t.armor + "-----"
			var b strings.Builder
			found := false
			for i++; i < len(lines); i++ {
				offset += len(lines[i]) + 1
				if lines[i] == end {
					found = true
					break
				}
				b.WriteString(lines[i])
			}
			if !found {
				return nil, errors.New("hs/desc: unterminated object")
			}
			var err error
			t.object, err = base64Decode(b.String())
			if err != nil || len(t.object) == 0 {
				return nil, errors.New("hs/desc: invalid base64 object")
			}
		}
		out = append(out, t)
	}
	return out, nil
}

func one(tokens []token, name string, nargs int, armor string) (token, error) {
	var result token
	found := false
	for _, t := range tokens {
		if t.name != name {
			continue
		}
		if found || len(t.args) != nargs || t.armor != armor {
			return token{}, fmt.Errorf("hs/desc: invalid or duplicate %s", name)
		}
		found = true
		result = t
	}
	if !found {
		return token{}, fmt.Errorf("hs/desc: missing %s", name)
	}
	return result, nil
}

func base64Decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, " \t\r\n") {
		return nil, errors.New("hs/desc: whitespace inside base64 field")
	}
	if strings.Contains(s, "=") {
		return base64.StdEncoding.Strict().DecodeString(s)
	}
	return base64.RawStdEncoding.Strict().DecodeString(s)
}
func decodeSize(s string, n int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(n) {
		return nil, errors.New("hs/desc: oversized base64 field")
	}
	b, err := base64Decode(s)
	if err != nil || len(b) != n {
		return nil, errors.New("hs/desc: invalid base64 field length")
	}
	return b, nil
}
func uintField(s string, bits int) (uint64, error) {
	if len(s) == 0 {
		return 0, errors.New("hs/desc: empty integer")
	}
	for _, b := range s {
		if b < '0' || b > '9' {
			return 0, errors.New("hs/desc: invalid integer")
		}
	}
	return strconv.ParseUint(s, 10, bits)
}
func armor(name string, b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	fmt.Fprintf(&out, "-----BEGIN %s-----\n", name)
	for len(s) > 64 {
		out.WriteString(s[:64])
		out.WriteByte('\n')
		s = s[64:]
	}
	out.WriteString(s)
	fmt.Fprintf(&out, "\n-----END %s-----", name)
	return out.String()
}

type certificate struct {
	key     ed25519.PublicKey
	signer  ed25519.PublicKey
	expires time.Time
}

func parseCertificate(raw []byte, typ byte, expected []byte, now time.Time) (*certificate, error) {
	if len(raw) < 104 || len(raw) > MaxDescriptorSize || raw[0] != 1 || raw[1] != typ || raw[6] != 1 {
		return nil, errors.New("hs/desc: invalid Ed25519 certificate header")
	}
	c := &certificate{key: append(ed25519.PublicKey(nil), raw[7:39]...), expires: time.Unix(int64(binary.BigEndian.Uint32(raw[2:6]))*3600, 0)}
	if now.IsZero() || !now.Before(c.expires) {
		return nil, errors.New("hs/desc: expired certificate")
	}
	end := len(raw) - 64
	pos := 40
	for range int(raw[39]) {
		if end-pos < 4 {
			return nil, errors.New("hs/desc: truncated certificate extension")
		}
		n := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		typ, flags := raw[pos+2], raw[pos+3]
		pos += 4
		if n > end-pos {
			return nil, errors.New("hs/desc: truncated certificate extension data")
		}
		if typ == 4 {
			if n != 32 || c.signer != nil {
				return nil, errors.New("hs/desc: invalid signing-key extension")
			}
			c.signer = append(ed25519.PublicKey(nil), raw[pos:pos+n]...)
		} else if flags&1 != 0 {
			return nil, errors.New("hs/desc: unknown critical certificate extension")
		}
		pos += n
	}
	if pos != end || c.signer == nil {
		return nil, errors.New("hs/desc: missing signer or trailing certificate bytes")
	}
	if expected != nil && !bytes.Equal(c.signer, expected) {
		return nil, errors.New("hs/desc: certificate signer mismatch")
	}
	if err := hscrypto.ValidateEd25519PublicKey(c.signer); err != nil {
		return nil, err
	}
	if err := hscrypto.ValidateEd25519PublicKey(c.key); err != nil {
		return nil, err
	}
	if !ed25519.Verify(c.signer, raw[:end], raw[end:]) {
		return nil, errors.New("hs/desc: invalid certificate signature")
	}
	return c, nil
}

func certificateBody(typ byte, key, signer []byte, expires time.Time) ([]byte, error) {
	if typ != 8 && typ != 9 && typ != 11 {
		return nil, errors.New("hs/desc: unsupported certificate type")
	}
	if err := hscrypto.ValidateEd25519PublicKey(key); err != nil {
		return nil, err
	}
	if err := hscrypto.ValidateEd25519PublicKey(signer); err != nil {
		return nil, err
	}
	seconds := expires.Unix()
	if seconds <= 0 || seconds > int64(^uint32(0))*3600 {
		return nil, errors.New("hs/desc: invalid certificate expiration")
	}
	hours := (seconds + 3599) / 3600
	raw := []byte{1, typ}
	raw = binary.BigEndian.AppendUint32(raw, uint32(hours))
	raw = append(raw, 1)
	raw = append(raw, key...)
	raw = append(raw, 1, 0, 32, 4, 0)
	return append(raw, signer...), nil
}

// SigningCertificate certifies a short-term descriptor signing key with an
// offline blinded key. The result is binary cert-spec format (type 08).
func SigningCertificate(blinded *hscrypto.BlindedPrivateKey, signingKey ed25519.PublicKey, expires time.Time) ([]byte, error) {
	if blinded == nil || blinded.PublicKey() == nil {
		return nil, errors.New("hs/desc: missing blinded signing key")
	}
	raw, err := certificateBody(8, signingKey, blinded.PublicKey().Bytes(), expires)
	if err != nil {
		return nil, err
	}
	sig, err := blinded.Sign(raw)
	if err != nil {
		return nil, err
	}
	return append(raw, sig...), nil
}

func signCertificate(typ byte, key []byte, signing ed25519.PrivateKey, expires time.Time) ([]byte, error) {
	if err := validatePrivateKey(signing); err != nil {
		return nil, err
	}
	raw, err := certificateBody(typ, key, signing[32:], expires)
	if err != nil {
		return nil, err
	}
	return append(raw, ed25519.Sign(signing, raw)...), nil
}
func validatePrivateKey(k ed25519.PrivateKey) error {
	if len(k) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(k[:32]), k) {
		return errors.New("hs/desc: invalid Ed25519 private key")
	}
	return nil
}

// C Tor uses sign bit zero for the Montgomery-to-Edwards conversion.
func encryptionCertKey(raw []byte) ([]byte, error) {
	u, err := new(field.Element).SetBytes(raw)
	if err != nil || !bytes.Equal(u.Bytes(), raw) {
		return nil, errors.New("hs/desc: invalid Curve25519 key")
	}
	one := new(field.Element).One()
	numerator := new(field.Element).Subtract(u, one)
	denominator := new(field.Element).Add(u, one)
	if denominator.Equal(new(field.Element).Zero()) == 1 {
		return nil, errors.New("hs/desc: degenerate Curve25519 key")
	}
	denominator.Invert(denominator)
	key := new(field.Element).Multiply(numerator, denominator).Bytes()
	if err := hscrypto.ValidateEd25519PublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func validateX25519(raw []byte) error {
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return err
	}
	// Public-input validation only: this fixed scalar is not a protocol secret.
	probe, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if _, err = probe.ECDH(pub); err != nil {
		return errors.New("hs/desc: low-order X25519 key")
	}
	return nil
}

// decodeLinkSpecs retains the complete wire block, including unknown types.
// lspec.Lspec currently represents only known types, so consumers extending a
// circuit must use IntroPoint.LinkSpecifiers for lossless forwarding.
func decodeLinkSpecs(raw []byte) ([]lspec.Lspec, error) {
	if len(raw) < 1 {
		return nil, errors.New("hs/desc: missing link specifier count")
	}
	pos := 1
	counts := [4]int{}
	var specs []lspec.Lspec
	for range int(raw[0]) {
		if len(raw)-pos < 2 {
			return nil, errors.New("hs/desc: truncated link specifier")
		}
		typ, n := raw[pos], int(raw[pos+1])
		pos += 2
		if n > len(raw)-pos {
			return nil, errors.New("hs/desc: truncated link specifier body")
		}
		b := raw[pos : pos+n]
		pos += n
		if typ > 3 {
			continue
		}
		counts[typ]++
		want := [4]int{6, 18, 20, 32}
		if n != want[typ] || (typ >= 2 && counts[typ] > 1) {
			return nil, errors.New("hs/desc: invalid link specifier length or duplicate identity")
		}
		if typ <= 1 && binary.BigEndian.Uint16(b[n-2:]) == 0 {
			return nil, errors.New("hs/desc: zero introduction port")
		}
		if typ == 2 && bytes.Equal(b, make([]byte, 20)) {
			return nil, errors.New("hs/desc: zero relay identity")
		}
		if typ == 3 {
			if err := hscrypto.ValidateEd25519PublicKey(b); err != nil {
				return nil, err
			}
		}
		s, err := lspec.FromWire(typ, b)
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	if pos != len(raw) || counts[0] == 0 || counts[2] != 1 || counts[3] != 1 {
		return nil, errors.New("hs/desc: incomplete link specifiers or trailing bytes")
	}
	return specs, nil
}

func encodeLinkSpecs(ip IntroPoint) ([]byte, error) {
	if len(ip.LinkSpecifiers) > 0 {
		if _, err := decodeLinkSpecs(ip.LinkSpecifiers); err != nil {
			return nil, err
		}
		return append([]byte(nil), ip.LinkSpecifiers...), nil
	}
	if len(ip.LinkSpecs) > 255 {
		return nil, errors.New("hs/desc: too many link specifiers")
	}
	raw := []byte{byte(len(ip.LinkSpecs))}
	for _, s := range ip.LinkSpecs {
		if s == (lspec.Lspec{}) {
			return nil, errors.New("hs/desc: uninitialized link specifier")
		}
		b, err := s.Bytes()
		if err != nil {
			return nil, err
		}
		if len(b) > 255 {
			return nil, errors.New("hs/desc: oversized link specifier")
		}
		raw = append(raw, s.Type(), byte(len(b)))
		raw = append(raw, b...)
	}
	if _, err := decodeLinkSpecs(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
