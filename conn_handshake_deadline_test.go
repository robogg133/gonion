package gonion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	cells "github.com/robogg133/gonion/pkg/cells/base"
)

// deadlineUnsupportedConn mirrors the upstream obfs4 connection: SetDeadline
// deliberately reports ENOTSUP. A root handshake must not depend on it.
type deadlineUnsupportedConn struct{ net.Conn }

func (c deadlineUnsupportedConn) SetDeadline(time.Time) error { return syscall.ENOTSUP }
func (c deadlineUnsupportedConn) SetWriteDeadline(time.Time) error {
	return syscall.ENOTSUP
}

// handshakeFixture is a generated relay identity and link certificate chain,
// valid for the verifier used by NewConn. It is not a Tor fixture: it exists
// only to drive an offline link handshake deterministically.
type handshakeFixture struct {
	tlsCert tls.Certificate
	certs   map[uint8][]byte
}

func newHandshakeFixture(t *testing.T) handshakeFixture {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gonion offline relay"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	rsaDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(rsaDER)
	if err != nil {
		t.Fatal(err)
	}

	identityPub, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPub, signingPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// cert4: signing key, signed by the Ed25519 identity key.
	cert4 := buildTorEdCert(t, cells.CERTS_IDENTITY_V_SIGNING_CERT, 1, signingPub, identityPub, identityPriv)
	// cert5: TLS cert digest, signed by the signing key.
	tlsDigest := sha256.Sum256(rsaDER)
	cert5 := buildTorEdCert(t, cells.CERTS_SIGNING_V_TLS_CERT, 3, tlsDigest[:], signingPub, signingPriv)
	// cert7: RSA identity -> Ed25519 identity cross-certificate.
	cert7 := buildRSAEdCrossCert(t, identityPub, rsaKey)

	return handshakeFixture{
		tlsCert: tls.Certificate{Certificate: [][]byte{rsaDER}, PrivateKey: rsaKey, Leaf: leaf},
		certs: map[uint8][]byte{
			cells.CERTS_RSA_ID_X509:             rsaDER,
			cells.CERTS_IDENTITY_V_SIGNING_CERT: cert4,
			cells.CERTS_SIGNING_V_TLS_CERT:      cert5,
			cells.CERTS_RSA_ID_V_IDENTITY:       cert7,
		},
	}
}

func buildTorEdCert(t *testing.T, certType, keyType uint8, certifiedKey, signerPub []byte, signer ed25519.PrivateKey) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteByte(1) // version
	b.WriteByte(certType)
	var expiration [4]byte
	binary.BigEndian.PutUint32(expiration[:], uint32(time.Now().Add(time.Hour).Unix()/3600))
	b.Write(expiration[:])
	b.WriteByte(keyType)
	b.Write(certifiedKey)
	b.WriteByte(1) // one extension
	var extLength [2]byte
	binary.BigEndian.PutUint16(extLength[:], 32)
	b.Write(extLength[:])
	b.WriteByte(4) // signed-with-ed25519-key
	b.WriteByte(0)
	b.Write(signerPub)
	b.Write(ed25519.Sign(signer, b.Bytes()))
	return b.Bytes()
}

func buildRSAEdCrossCert(t *testing.T, edPub []byte, rsaKey *rsa.PrivateKey) []byte {
	t.Helper()
	body := make([]byte, 36)
	copy(body, edPub)
	binary.BigEndian.PutUint32(body[32:], uint32(time.Now().Add(time.Hour).Unix()/3600))
	digest := sha256.Sum256(append([]byte("Tor TLS RSA/Ed25519 cross-certificate"), body...))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, 0, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 0, 37+len(signature))
	out = append(out, body...)
	out = append(out, byte(len(signature)))
	return append(out, signature...)
}

func variableCellFrame(circuitID uint32, command uint8, payload []byte) []byte {
	frame := make([]byte, 7+len(payload))
	binary.BigEndian.PutUint32(frame[:4], circuitID)
	frame[4] = command
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(payload)))
	copy(frame[7:], payload)
	return frame
}

func certsPayload(certs map[uint8][]byte) []byte {
	order := []uint8{
		cells.CERTS_RSA_ID_X509,
		cells.CERTS_IDENTITY_V_SIGNING_CERT,
		cells.CERTS_SIGNING_V_TLS_CERT,
		cells.CERTS_RSA_ID_V_IDENTITY,
	}
	var payload bytes.Buffer
	payload.WriteByte(byte(len(order)))
	for _, certType := range order {
		cert := certs[certType]
		payload.WriteByte(certType)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(cert)))
		payload.Write(length[:])
		payload.Write(cert)
	}
	return payload.Bytes()
}

func readClientVersions(conn net.Conn) error {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[2] != cells.COMMAND_VERSIONS {
		return fmt.Errorf("expected VERSIONS, got command %d", header[2])
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
	_, err := io.ReadFull(conn, body)
	return err
}

// serveLinkHandshake answers a complete link handshake over an already
// connected pair. It closes ready once the handshake is complete, then drains
// the connection so the peer's TLS close_notify cannot block.
func serveLinkHandshake(raw net.Conn, fixture handshakeFixture, ready chan<- struct{}) error {
	server := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{fixture.tlsCert},
		MaxVersion:   tls.VersionTLS12,
	})
	if err := server.Handshake(); err != nil {
		return err
	}

	if err := readClientVersions(server); err != nil {
		return err
	}
	if _, err := server.Write((&cells.VersionCell{CircuitID: 0, Versions: []uint16{5}}).Serialize()); err != nil {
		return err
	}
	if _, err := server.Write(variableCellFrame(0, cells.COMMAND_CERTS, certsPayload(fixture.certs))); err != nil {
		return err
	}
	if _, err := server.Write(variableCellFrame(0, cells.COMMAND_AUTH_CHALLANGE, make([]byte, 32))); err != nil {
		return err
	}
	coder := cells.NewCellCoder(cells.AllKnownCells)
	if err := coder.WriteCell(&cells.NetInfoCell{CircuitID: 0, OtherAddr: netip.MustParseAddr("192.0.2.1")}, server); err != nil {
		return err
	}
	// The pair is synchronous, so the client's NETINFO write only completes
	// once this side consumes it.
	if _, err := io.ReadFull(server, make([]byte, 5+cells.CELL_BODY_LEN)); err != nil {
		return err
	}
	close(ready)
	_, _ = io.Copy(io.Discard, server)
	return nil
}

// TestNewConnToleratesUnsupportedHandshakeDeadline proves that a transport
// whose SetDeadline returns ENOTSUP still completes a valid link handshake.
func TestNewConnToleratesUnsupportedHandshakeDeadline(t *testing.T) {
	fixture := newHandshakeFixture(t)
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()

	ready := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() { serverErr <- serveLinkHandshake(serverRaw, fixture, ready) }()

	conn, err := newConn(deadlineUnsupportedConn{Conn: clientRaw}, io.Discard, false, 10*time.Second)
	if err != nil {
		t.Fatalf("NewConn failed for an ENOTSUP deadline transport: %v", err)
	}
	<-ready
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("offline server handshake failed: %v", err)
	}
}

// TestNewConnHandshakeDeadlineClosesStalledLink proves that a stalled link
// handshake is terminated by the context deadline, even though the transport
// cannot enforce a socket deadline. The socket must also be closed.
func TestNewConnHandshakeDeadlineClosesStalledLink(t *testing.T) {
	fixture := newHandshakeFixture(t)
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()

	stalled := make(chan struct{})
	serverRead := make(chan error, 1)
	go func() {
		server := tls.Server(serverRaw, &tls.Config{
			Certificates: []tls.Certificate{fixture.tlsCert},
			MaxVersion:   tls.VersionTLS12,
		})
		if err := server.Handshake(); err != nil {
			serverRead <- err
			return
		}
		defer server.Close()
		if err := readClientVersions(server); err != nil {
			serverRead <- err
			return
		}
		// Do not answer VERSIONS. The client must time out.
		close(stalled)
		var b [1]byte
		_, err := server.Read(b[:])
		serverRead <- err
	}()

	const timeout = 400 * time.Millisecond
	start := time.Now()
	conn, err := newConn(deadlineUnsupportedConn{Conn: clientRaw}, io.Discard, false, timeout)
	elapsed := time.Since(start)
	if err == nil {
		_ = conn.Close()
		t.Fatal("stalled handshake unexpectedly succeeded")
	}
	select {
	case <-stalled:
	default:
		t.Fatal("client never reached the stalled link handshake stage")
	}
	if elapsed+50*time.Millisecond < timeout {
		t.Fatalf("handshake failed before the deadline elapsed: %v", elapsed)
	}
	select {
	case readErr := <-serverRead:
		if readErr == nil {
			t.Fatal("peer read succeeded after the handshake deadline")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake deadline did not close the socket")
	}
}
