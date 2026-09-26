package desc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/lspec"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testOptions(t *testing.T) EncodeOptions {
	t.Helper()
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	blinded, err := hscrypto.BlindPrivateKey(identity, 1234, 1440)
	if err != nil {
		t.Fatal(err)
	}
	relayKey, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{2}, 32))
	encKey, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	auth := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	relayID := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	addr, err := lspec.FromWire(0, []byte{127, 0, 0, 1, 0x23, 0x29})
	if err != nil {
		t.Fatal(err)
	}
	return EncodeOptions{BlindedKey: blinded, SigningKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32)), RevisionCounter: 1<<63 + 42, CertificateExpiry: time.Now().Add(48 * time.Hour), IntroPoints: []IntroPoint{{OnionKey: relayKey.PublicKey().Bytes(), EncKey: encKey.PublicKey().Bytes(), AuthKey: auth[32:], LinkSpecs: []lspec.Lspec{addr, lspec.NewNodeID([20]byte{7}), lspec.NewEd25519ID(ed25519.PublicKey(relayID[32:]))}}}}
}
func mustEncode(t *testing.T, o EncodeOptions) []byte {
	t.Helper()
	raw, err := Encode(o)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDescriptorRoundTrip(t *testing.T) {
	o := testOptions(t)
	raw := mustEncode(t, o)
	d, err := Decode(raw, o.BlindedKey.PublicKey(), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != 3 || d.LifetimeSeconds != 10800 || d.RevisionCounter != o.RevisionCounter || len(d.IntroPoints) != 1 {
		t.Fatalf("bad metadata: %+v", d)
	}
	ip := d.IntroPoints[0]
	if !bytes.Equal(ip.OnionKey, o.IntroPoints[0].OnionKey) || !bytes.Equal(ip.EncKey, o.IntroPoints[0].EncKey) || bytes.Equal(ip.OnionKey, ip.EncKey) || !bytes.Equal(ip.AuthKey, o.IntroPoints[0].AuthKey) {
		t.Fatal("introduction keys confused")
	}
	if len(ip.LinkSpecs) != 3 || len(ip.LinkSpecifiers) != 65 {
		t.Fatalf("bad link specifier block: %x", ip.LinkSpecifiers)
	}
	if _, err := parseCertificate(ip.AuthKeyCertificate, 9, d.SigningKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCertificate(ip.EncKeyCertificate, 11, d.SigningKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	outer, err := Parse(raw)
	if err != nil || len(outer.IntroPoints) != 0 || outer.Subcredential != nil {
		t.Fatal("Parse must only validate outer wrapper", err)
	}
	sub, err := deriveSubcredential(o.BlindedKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	middle, err := hscrypto.DecryptDescriptor(d.BlindedKey, sub, d.RevisionCounter, hscrypto.SuperencryptedLayer, d.SuperencryptedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(middle)%10000 != 0 {
		t.Fatal("outer layer not padded to 10k")
	}
	if bytes.Count(middle, []byte("auth-client ")) != 16 {
		t.Fatal("public service not padded with 16 fake clients")
	}
	o.IntroPoints = nil
	raw = mustEncode(t, o)
	empty, err := Decode(raw, o.BlindedKey.PublicKey(), nil, time.Now())
	if err != nil || len(empty.IntroPoints) != 0 {
		t.Fatal("zero-introduction descriptor", err)
	}
	// Offline certificate route produces the same public identity without having
	// the blinded private key available to the encoding operation.
	o.BlindedPublicKey = o.BlindedKey.PublicKey()
	o.SigningKeyCertificate, err = SigningCertificate(o.BlindedKey, ed25519.PublicKey(o.SigningKey[32:]), o.CertificateExpiry)
	if err != nil {
		t.Fatal(err)
	}
	o.BlindedKey = nil
	if _, err := Decode(mustEncode(t, o), o.BlindedPublicKey, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizedDescriptor(t *testing.T) {
	o := testOptions(t)
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o.AuthorizedClients = []*ecdh.PublicKey{client.PublicKey()}
	raw := mustEncode(t, o)
	for _, key := range []*ecdh.PrivateKey{nil, wrong} {
		if _, err := Decode(raw, o.BlindedKey.PublicKey(), key, time.Now()); !errors.Is(err, ErrClientAuthorization) {
			t.Fatalf("unauthorized decode: %v", err)
		}
	}
	if _, err := Decode(raw, o.BlindedKey.PublicKey(), client, time.Now()); err != nil {
		t.Fatal(err)
	}
	o.AuthorizedClients = nil
	if _, err := Decode(mustEncode(t, o), o.BlindedKey.PublicKey(), wrong, time.Now()); err != nil {
		t.Fatal("configured client key must not break public service", err)
	}
}

func TestTorAuthorizedClientVector(t *testing.T) {
	// Tor src/test/test_hs_descriptor.c:test_build_authorized_client.
	private, err := ecdh.X25519().NewPrivateKey(decodeHex(t, "d023b674d993a5c8446bd2ca97e9961149b3c0e88c7dc14e8777744dd3468d6a"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdh.X25519().NewPublicKey(decodeHex(t, "8c1298fa6050e372f8598f6deca32e27b0ad457741422c2629ebb132cf7fae37"))
	if err != nil {
		t.Fatal(err)
	}
	cookie := decodeHex(t, "07d087f1d8c68393721f6e70316d3b29")
	got, err := buildAuthClient(bytes.Repeat([]byte{42}, 32), private, public, cookie, bytes.Repeat([]byte{1}, 16))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.id, decodeHex(t, "ec19b7ff4d2dda13")) || !bytes.Equal(got.cookie, decodeHex(t, "b21222be13f385f355bd07b2381f9f29")) {
		t.Fatalf("Tor cookie vector mismatch: %x %x", got.id, got.cookie)
	}
}

func TestTorCertificatesAndBadSignature(t *testing.T) {
	// Binary certificate fixtures from Tor test_hs_descriptor.c. Tor's negative
	// introduction fixture deliberately mixes different signing keys; validate
	// each certificate separately, and reject that mix in an intro point.
	fixtures := []struct {
		typ     byte
		encoded string
	}{
		{9, "AQkACOhAAQW8ltYZMIWpyrfyE/b4Iyi8CNybCwYs6ADk7XfBaxsFAQAgBAD3/BE4XojGE/N2bW/wgnS9r2qlrkydGyuCKIGayYx3haZ39LD4ZTmSMRxwmplMAqzG/XNP0Kkpg4p2/VnLFJRdU1SMFo1lgQ4P0bqw7Tgx200fulZ4KUM5z5V7m+a/mgY="},
		{11, "AQsACOhZAUpNvCZ1aJaaR49lS6MCdsVkhVGVrRqoj0Y2T4SzroAtAQAgBABFOcGglbTt1DF5nKTE/gU3Fr8ZtlCIOhu1A+F5LM7fqCUupfesg0KTHwyIZOYQbJuM5/he/jDNyLy9woPJdjkxywaY2RPUxGjLYtMQV0E8PUxWyICV+7y52fTCYaKpYQw="},
	}
	for _, f := range fixtures {
		raw, err := base64Decode(f.encoded)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Unix(int64(binary.BigEndian.Uint32(raw[2:6]))*3600-1, 0)
		c, err := parseCertificate(raw, f.typ, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseCertificate(raw, f.typ, c.signer, c.expires); err == nil {
			t.Fatal("expired certificate accepted")
		}
		for _, offset := range []int{0, 1, 6, 7, 39, 40, len(raw) - 1} {
			bad := bytes.Clone(raw)
			bad[offset] ^= 1
			if _, err := parseCertificate(bad, f.typ, c.signer, now); err == nil {
				t.Fatalf("bad certificate byte %d accepted", offset)
			}
		}
		if _, err := parseCertificate(raw, f.typ, bytes.Repeat([]byte{9}, 32), now); err == nil {
			t.Fatal("wrong cert signer accepted")
		}
	}
	raw, err := os.ReadFile("testdata/tor-bad-signature.desc")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenize(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := one(tokens, "descriptor-signing-key-cert", 0, "ED25519 CERT")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1502661599, 0) // Exact Tor test_decode_bad_signature time.
	c, err := parseCertificate(cert.object, 8, nil, now)
	if err != nil {
		t.Fatal("Tor wrapper certificate must be valid", err)
	}
	if _, err := parseOuter(raw, c.signer, now); err == nil || !strings.Contains(err.Error(), "descriptor signature") {
		t.Fatalf("expected Tor bad signature rejection, got %v", err)
	}
	// Removing only the invalid unsigned leading space recovers the Tor
	// descriptor's valid outer signature, without regenerating any signature.
	corrected := bytes.Replace(raw, []byte("\n signature "), []byte("\nsignature "), 1)
	if _, err := parseOuter(corrected, c.signer, now); err != nil {
		t.Fatal("Tor signature verification", err)
	}
	changed := bytes.Replace(corrected, []byte("revision-counter 42"), []byte("revision-counter 43"), 1)
	if _, err := parseOuter(changed, c.signer, now); err == nil {
		t.Fatal("Tor signature accepted changed revision")
	}
}

func resign(raw []byte, key ed25519.PrivateKey) []byte {
	i := bytes.LastIndex(raw, []byte("\nsignature "))
	prefix := raw[:i+1]
	sig := ed25519.Sign(key, append([]byte(signaturePrefix), prefix...))
	return append(bytes.Clone(prefix), []byte("signature "+base64.RawStdEncoding.EncodeToString(sig)+"\n")...)
}

func TestRejectMalformedDescriptors(t *testing.T) {
	o := testOptions(t)
	raw := mustEncode(t, o)
	blinded := o.BlindedKey.PublicKey()
	wrong := hscrypto.BlindPk(blinded.Pk(), 1235, 1440)
	if _, err := Decode(raw, wrong, nil, time.Now()); err == nil {
		t.Fatal("wrong blinded key accepted")
	}
	if _, err := Decode(raw, blinded, nil, o.CertificateExpiry.Add(time.Hour)); err == nil {
		t.Fatal("expired descriptor accepted")
	}
	bads := [][]byte{
		[]byte("version 3\nlifetime 180\nintroduction-points auth-key\nAAAA\n"),
		bytes.Repeat([]byte{'x'}, MaxDescriptorSize+1),
		append(bytes.Clone(raw), []byte("unsigned-field x\n")...),
		bytes.Replace(raw, []byte("hs-descriptor 3"), []byte("hs-descriptor 4"), 1),
		bytes.Replace(raw, []byte("descriptor-lifetime 180"), []byte("descriptor-lifetime 29"), 1),
		bytes.Replace(raw, []byte("revision-counter "), []byte("revision-counter -"), 1),
		bytes.Replace(raw, []byte("revision-counter "), []byte("revision-counter 18446744073709551616"), 1),
		bytes.Replace(raw, []byte("descriptor-lifetime 180\n"), []byte("descriptor-lifetime 180\ndescriptor-lifetime 180\n"), 1),
		bytes.Replace(raw, []byte("superencrypted\n"), []byte("encrypted\n"), 1),
	}
	for i, bad := range bads {
		if _, err := Decode(bad, blinded, nil, time.Now()); err == nil {
			t.Fatalf("malformed descriptor %d accepted", i)
		}
	}
	// Correctly re-sign a changed revision to reach the MAC/KDF binding check.
	altered := bytes.Replace(raw, []byte(fmt.Sprintf("revision-counter %d", o.RevisionCounter)), []byte("revision-counter 1"), 1)
	if _, err := Decode(resign(altered, o.SigningKey), blinded, nil, time.Now()); err == nil {
		t.Fatal("wrong revision MAC accepted")
	}
}

// rewriteLayers keeps the wrapper and layer authentication valid so negative
// tests reach the parsers rather than stopping at the outer signature.
func rewriteLayers(t *testing.T, o EncodeOptions, raw []byte, middleChange, innerChange func([]byte) []byte) []byte {
	t.Helper()
	d, err := parseOuter(raw, o.BlindedKey.PublicKey().Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sub, err := deriveSubcredential(o.BlindedKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	middle, err := hscrypto.DecryptDescriptor(d.BlindedKey, sub, d.RevisionCounter, hscrypto.SuperencryptedLayer, d.SuperencryptedRaw)
	if err != nil {
		t.Fatal(err)
	}
	middle, err = unpad(middle)
	if err != nil {
		t.Fatal(err)
	}
	if innerChange != nil {
		tokens, err := tokenize(middle)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := one(tokens, "encrypted", 0, "MESSAGE")
		if err != nil {
			t.Fatal(err)
		}
		inner, err := hscrypto.DecryptDescriptor(d.BlindedKey, sub, d.RevisionCounter, hscrypto.EncryptedLayer, enc.object)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := hscrypto.EncryptDescriptor(d.BlindedKey, sub, d.RevisionCounter, hscrypto.EncryptedLayer, innerChange(inner))
		if err != nil {
			t.Fatal(err)
		}
		middle = bytes.Replace(middle, []byte(armor("MESSAGE", enc.object)), []byte(armor("MESSAGE", changed)), 1)
	}
	if middleChange != nil {
		middle = middleChange(middle)
	}
	enc, err := hscrypto.EncryptDescriptor(d.BlindedKey, sub, d.RevisionCounter, hscrypto.SuperencryptedLayer, middle)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(armor("MESSAGE", d.SuperencryptedRaw)), []byte(armor("MESSAGE", enc)), 1)
	return resign(raw, o.SigningKey)
}

func TestLayerParserValidation(t *testing.T) {
	o := testOptions(t)
	raw := mustEncode(t, o)
	changes := []func([]byte) []byte{
		func(b []byte) []byte {
			return bytes.Replace(b, []byte("create2-formats 2"), []byte("create2-formats 1"), 1)
		},
		func(b []byte) []byte { return append([]byte("create2-formats 2\n"), b...) },
		func(b []byte) []byte { return bytes.Replace(b, []byte("auth-key\n"), []byte("missing-auth-key\n"), 1) },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte("enc-key-cert\n"), []byte("missing-enc-key-cert\n"), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte("enc-key ntor "+base64.StdEncoding.EncodeToString(o.IntroPoints[0].EncKey)), []byte("enc-key ntor "+base64.StdEncoding.EncodeToString(o.IntroPoints[0].OnionKey)), 1)
		},
		func(b []byte) []byte { return append(b, 0, 'x') },
	}
	for i, change := range changes {
		modified := rewriteLayers(t, o, raw, nil, change)
		if _, err := Decode(modified, o.BlindedKey.PublicKey(), nil, time.Now()); err == nil {
			t.Fatalf("invalid inner layer %d accepted", i)
		}
	}
	for i, change := range []func([]byte) []byte{
		func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("auth-client "), []byte("no-auth-client ")) },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte("desc-auth-type x25519"), []byte("desc-auth-type unsupported"), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte("desc-auth-ephemeral-key "), []byte("desc-auth-ephemeral-key AAA"), 1)
		},
		func(b []byte) []byte { return append(b, 0, 'x') },
	} {
		modified := rewriteLayers(t, o, raw, change, nil)
		if _, err := Decode(modified, o.BlindedKey.PublicKey(), nil, time.Now()); err == nil {
			t.Fatalf("invalid middle layer %d accepted", i)
		}
	}
	modified := rewriteLayers(t, o, raw, func(b []byte) []byte { return append(b, '\n') }, func(b []byte) []byte { return append([]byte("future-field yes\n"), b...) })
	if _, err := Decode(modified, o.BlindedKey.PublicKey(), nil, time.Now()); err != nil {
		t.Fatal("unknown field or final middle newline rejected", err)
	}
}

func TestUnknownAndBoundedLinkSpecifiers(t *testing.T) {
	o := testOptions(t)
	raw, err := encodeLinkSpecs(o.IntroPoints[0])
	if err != nil {
		t.Fatal(err)
	}
	raw[0]++
	raw = append(raw, 99, 3, 1, 2, 3)
	o.IntroPoints[0].LinkSpecifiers = raw
	d, err := Decode(mustEncode(t, o), o.BlindedKey.PublicKey(), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.IntroPoints[0].LinkSpecifiers, raw) {
		t.Fatal("unknown link specifier lost")
	}
	for n := 0; n < len(raw); n++ {
		if _, err := decodeLinkSpecs(raw[:n]); err == nil {
			t.Fatalf("truncated specifiers accepted at %d", n)
		}
	}
	duplicate := bytes.Clone(raw)
	duplicate[0]++
	duplicate = append(duplicate, 2, 20)
	duplicate = append(duplicate, bytes.Repeat([]byte{1}, 20)...)
	if _, err := decodeLinkSpecs(duplicate); err == nil {
		t.Fatal("duplicate identity accepted")
	}
}

type fetchCirc struct {
	capi.Circ
	stream *fetchStream
	target string
	hop    int
	closed atomic.Bool
}

func (c *fetchCirc) HopCount() int { return 3 }
func (c *fetchCirc) NewStream(target string, hop int) (capi.Stream, error) {
	c.target = target
	c.hop = hop
	return c.stream, nil
}
func (c *fetchCirc) Close() error { c.closed.Store(true); return c.stream.conn.Close() }

type fetchStream struct {
	capi.Stream
	conn net.Conn
}

func (s *fetchStream) Conn() net.Conn { return s.conn }
func (s *fetchStream) Free() error    { return s.conn.Close() }

func testHSDir() common.RouterStatus {
	var r common.RouterStatus
	r.StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] = true
	r.ProtoVersions.HSDir.SetValue(common.VERSION_2, true)
	return r
}

func TestFetchBeginDir(t *testing.T) {
	o := testOptions(t)
	raw := mustEncode(t, o)
	a, b := net.Pipe()
	defer b.Close()
	circ := &fetchCirc{stream: &fetchStream{conn: a}}
	request := make(chan *http.Request, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		req, err := http.ReadRequest(bufio.NewReader(b))
		if err != nil {
			return
		}
		request <- req
		fmt.Fprintf(b, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n", len(raw))
		b.Write(raw)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := Fetch(ctx, circ, testHSDir(), o.BlindedKey.PublicKey(), 1234, 1440, 1)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if d.RevisionCounter != o.RevisionCounter || circ.target != "dir" || circ.hop != 2 {
		t.Fatal("fetch did not use final-hop BEGIN_DIR")
	}
	req := <-request
	if req.RequestURI != "/tor/hs/3/"+base64.RawStdEncoding.EncodeToString(o.BlindedKey.PublicKey().Bytes()) {
		t.Fatalf("incorrect fetch URL: %s", req.RequestURI)
	}
}

func TestPublishBeginDir(t *testing.T) {
	raw := mustEncode(t, testOptions(t))
	for _, response := range []string{"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", "HTTP/1.0 400 Bad\r\nContent-Length: 0\r\n\r\n", "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nx"} {
		a, b := net.Pipe()
		circ := &fetchCirc{stream: &fetchStream{conn: a}}
		request := make(chan error, 1)
		go func() {
			defer b.Close()
			req, err := http.ReadRequest(bufio.NewReader(b))
			if err == nil {
				var body []byte
				body, err = io.ReadAll(req.Body)
				if err == nil && (req.Method != http.MethodPost || req.RequestURI != "/tor/hs/3/publish" || !bytes.Equal(body, raw)) {
					err = errors.New("incorrect descriptor POST")
				}
			}
			request <- err
			io.WriteString(b, response)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := Publish(ctx, circ, testHSDir(), raw)
		cancel()
		if wantOK := strings.Contains(response, "Content-Length: 0") && strings.Contains(response, "200 OK"); (err == nil) != wantOK {
			t.Fatalf("publish response accepted incorrectly: %v", err)
		}
		if err := <-request; err != nil {
			t.Fatal(err)
		}
		if circ.target != "dir" || circ.hop != 2 {
			t.Fatal("publication bypassed final-hop BEGIN_DIR")
		}
	}
	if err := Publish(context.Background(), nil, testHSDir(), []byte("unsigned")); err == nil {
		t.Fatal("unsigned descriptor reached publication transport")
	}
}

func TestFetchRequiresV3HSDir(t *testing.T) {
	o := testOptions(t)
	for _, relay := range []common.RouterStatus{{}, testHSDir()} {
		if relay.StatusFlags[common.FLAG_HIDDEN_SERVICE_DIR] {
			relay.ProtoVersions.HSDir.SetValue(common.VERSION_2, false)
			relay.ProtoVersions.HSDir.SetValue(common.VERSION_1, true)
		}
		_, err := Fetch(context.Background(), nil, relay, o.BlindedKey.PublicKey(), 0, 0, 0)
		if err == nil || !strings.Contains(err.Error(), "HSDir=2") {
			t.Fatalf("unsupported HSDir: %v", err)
		}
	}
}

func TestFetchLimitsAndCancellation(t *testing.T) {
	o := testOptions(t)
	for _, response := range []string{
		"HTTP/1.0 200 OK\r\nContent-Length: 50001\r\n\r\n",
		"HTTP/1.0 200 OK\r\nX-Large: " + strings.Repeat("x", 17000) + "\r\n\r\n",
		"HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
		"HTTP/1.0 404 Missing\r\n\r\n",
		"",
	} {
		a, b := net.Pipe()
		circ := &fetchCirc{stream: &fetchStream{conn: a}}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			if _, err := http.ReadRequest(bufio.NewReader(b)); err != nil {
				return
			}
			if response != "" {
				io.WriteString(b, response)
			} else {
				io.Copy(io.Discard, b)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err := Fetch(ctx, circ, testHSDir(), o.BlindedKey.PublicKey(), 0, 0, 0)
		cancel()
		<-done
		if err == nil {
			t.Fatal("invalid or stalled HTTP response accepted")
		}
	}
}

func TestCertificateExtensionsAndEarliestExpiry(t *testing.T) {
	o := testOptions(t)
	cert, err := SigningCertificate(o.BlindedKey, ed25519.PublicKey(o.SigningKey[32:]), o.CertificateExpiry)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Clone(cert[:len(cert)-64])
	withExtension := func(extension []byte) []byte {
		b := bytes.Clone(body)
		b[39]++
		b = append(b, extension...)
		sig, err := o.BlindedKey.Sign(b)
		if err != nil {
			t.Fatal(err)
		}
		return append(b, sig...)
	}
	unknown := withExtension([]byte{0, 1, 99, 0, 7})
	if _, err := parseCertificate(unknown, 8, o.BlindedKey.PublicKey().Bytes(), time.Now()); err != nil {
		t.Fatal("noncritical extension rejected", err)
	}
	for _, bad := range [][]byte{
		withExtension([]byte{0, 1, 99, 1, 7}), // Unknown critical extension.
		withExtension([]byte{0, 2, 99, 0, 7}), // Truncated extension payload.
		withExtension(body[40:]),              // Duplicate signing-key extension.
	} {
		if _, err := parseCertificate(bad, 8, o.BlindedKey.PublicKey().Bytes(), time.Now()); err == nil {
			t.Fatal("invalid signed extension accepted")
		}
	}

	expiry := time.Now().Add(2 * time.Hour).Truncate(time.Hour)
	auth, err := signCertificate(9, o.IntroPoints[0].AuthKey, o.SigningKey, expiry)
	if err != nil {
		t.Fatal(err)
	}
	raw := rewriteLayers(t, o, mustEncode(t, o), nil, func(inner []byte) []byte {
		tokens, err := tokenize(inner)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := one(tokens, "auth-key", 0, "ED25519 CERT")
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Replace(inner, []byte(armor("ED25519 CERT", tok.object)), []byte(armor("ED25519 CERT", auth)), 1)
	})
	d, err := Decode(raw, o.BlindedKey.PublicKey(), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !d.CertificateExpiry.Equal(expiry) {
		t.Fatal("cache expiry did not include introduction certificate")
	}
	if _, err := Decode(raw, o.BlindedKey.PublicKey(), nil, expiry); err == nil {
		t.Fatal("expired introduction certificate accepted")
	}
}

func FuzzDescriptorParsers(f *testing.F) {
	f.Add([]byte("hs-descriptor 3\n"))
	f.Add([]byte("create2-formats 2\n"))
	f.Add([]byte{3, 0, 6, 127, 0, 0, 1, 0, 80})
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxDescriptorSize+1 {
			return
		}
		parseOuter(b, nil, time.Unix(1502661599, 0))
		parseInner(&Descriptor{SigningKey: ed25519.PublicKey(signing[32:])}, b, time.Unix(1502661599, 0))
		decodeLinkSpecs(b)
		for _, typ := range []byte{8, 9, 11} {
			parseCertificate(b, typ, nil, time.Unix(1502661599, 0))
		}
	})
}
