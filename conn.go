package gonion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/crypto"
)

const CONNECTION_TIMEOUT = 60 * time.Second

type Conn struct {
	socket         net.Conn
	circuits       *circuits
	ProtcolVersion uint16

	netInfo cells.NetInfoCell

	Cert *x509.Certificate

	userDataPipeWriter *io.PipeWriter
	userDataPipeReader *io.PipeReader

	mu sync.RWMutex

	writeCall chan []byte
	ctx       context.Context
	ctxCancel context.CancelCauseFunc

	guardID uint32
	exitID  uint32

	cellBodyLen int
}

// NewConn performs the Tor link handshake on c.
// logOut receives structured logs when debug is false; when debug is true, logs go to stderr in console form.
func NewConn(c net.Conn, logOut io.Writer, debug bool) (*Conn, error) {
	base := newLogger(logOut, debug)
	remote := ""
	if ra := c.RemoteAddr(); ra != nil {
		remote = ra.String()
	}
	base = base.With().
		Str("component", "conn").
		Str("remote", remote).
		Logger()

	ctx, cancel := context.WithCancelCause(withLogger(context.Background(), base))
	conn := &Conn{
		writeCall: make(chan []byte, 4096),
		ctx:       ctx,
		ctxCancel: cancel,
		circuits: &circuits{
			circs: make(map[uint32]*Circuit),
		},
		cellBodyLen: cells.CELL_BODY_LEN,
	}

	log := logger(ctx)
	log.Info().Msg("link handshake starting")

	var err error
	conn.socket, conn.Cert, err = setupTls(ctx, c)
	if err != nil {
		cancel(err)
		return nil, fail(ctx, ErrTLS, "tls handshake failed", err)
	}
	log.Debug().Msg("tls established")

	if err := conn.socket.SetDeadline(time.Now().Add(CONNECTION_TIMEOUT)); err != nil {
		cancel(err)
		return nil, fail(ctx, ErrIO, "set handshake deadline failed", err)
	}

	conn.ProtcolVersion, err = negotiateVersion(ctx, conn.socket, conn.socket)
	if err != nil {
		cancel(err)
		return nil, err
	}

	// Enrich context logger with negotiated version for all subsequent work on this conn.
	conn.ctx = base.With().Uint16("link_version", conn.ProtcolVersion).Logger().WithContext(conn.ctx)
	ctx = conn.ctx
	log = logger(ctx)
	log.Info().Uint16("link_version", conn.ProtcolVersion).Msg("version negotiated")

	coder := cells.NewCellCoder(cells.AllKnownCells)

	pkg, err := coder.ReadCell(conn.socket)
	if err != nil {
		cancel(err)
		return nil, fail(ctx, ErrIO, "read CERTS cell failed", err)
	}
	if pkg.ID() != cells.COMMAND_CERTS {
		pub := Publicf(ErrProtocolViolation, "expected CERTS, got command %d", pkg.ID())
		log.Error().Uint8("cmd", pkg.ID()).Msg("unexpected cell during handshake")
		cancel(pub)
		return nil, pub
	}

	certs := pkg.(*cells.CertsCell)
	var cert4 *crypto.TorCert
	var cert5 *crypto.TorCert
	for _, v := range certs.Certificates {
		switch v.Type {
		case 4:
			cert4, err = crypto.ParseIdentityVSigningCert(v.Cert)
			if err != nil {
				cancel(err)
				return nil, fail(ctx, ErrHandshake, "parse identity cert failed", err)
			}
		case 5:
			cert5, err = crypto.ParseIdentityVSigningCert(v.Cert)
			if err != nil {
				cancel(err)
				return nil, fail(ctx, ErrHandshake, "parse signing cert failed", err)
			}
		}
	}
	if err := crypto.VerifyConnection(cert4, cert5, conn.Cert.Raw); err != nil {
		cancel(err)
		return nil, fail(ctx, ErrHandshake, "certificate verification failed", err)
	}
	log.Debug().Msg("certs verified")

	if err := discardAuthChallenge(ctx, conn.socket); err != nil {
		cancel(err)
		return nil, err
	}

	pkg, err = coder.ReadCell(conn.socket)
	if err != nil {
		cancel(err)
		return nil, fail(ctx, ErrIO, "read NETINFO cell failed", err)
	}
	if pkg.ID() != cells.COMMAND_NETINFO {
		pub := Publicf(ErrProtocolViolation, "expected NETINFO, got command %d", pkg.ID())
		log.Error().Uint8("cmd", pkg.ID()).Msg("unexpected cell during handshake")
		cancel(pub)
		return nil, pub
	}

	netinfo := pkg.(*cells.NetInfoCell)
	conn.netInfo = *netinfo

	info := cells.NetInfoCell{
		CircuitID: 0,
		Timestamp: 0,
		OtherAddr: netip.MustParseAddrPort(conn.socket.RemoteAddr().String()).Addr(),
		MyAdress:  nil,
	}
	if err := coder.WriteCell(&info, conn.socket); err != nil {
		cancel(err)
		return nil, fail(ctx, ErrIO, "write NETINFO cell failed", err)
	}

	if err := conn.socket.SetDeadline(time.Time{}); err != nil {
		cancel(err)
		return nil, fail(ctx, ErrIO, "clear deadline failed", err)
	}

	log.Info().Msg("link ready")
	go conn.readLoop()
	go conn.writeLoop()

	return conn, nil
}

func (conn *Conn) Close() error {
	logger(conn.ctx).Info().Msg("closing connection")
	conn.ctxCancel(ErrClosed)
	return conn.socket.Close()
}

func (conn *Conn) Context() context.Context {
	return conn.ctx
}

func setupTls(ctx context.Context, c net.Conn) (net.Conn, *x509.Certificate, error) {
	tctx, cancel := context.WithTimeout(ctx, CONNECTION_TIMEOUT)
	defer cancel()

	tlsConn := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
	})

	if err := tlsConn.HandshakeContext(tctx); err != nil {
		return nil, nil, err
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, Public(ErrTLS, "no peer certificate")
	}
	return tlsConn, state.PeerCertificates[0], nil
}

func discardAuthChallenge(ctx context.Context, conn net.Conn) error {
	header := make([]byte, 7)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fail(ctx, ErrIO, "read AUTH_CHALLENGE header failed", err)
	}

	if uint8(header[4]) != cells.COMMAND_AUTH_CHALLANGE {
		logger(ctx).Error().
			Uint8("expected", cells.COMMAND_AUTH_CHALLANGE).
			Uint8("got", header[4]).
			Msg("invalid AUTH_CHALLENGE command")
		return Publicf(ErrProtocolViolation, "expected AUTH_CHALLENGE, got command %d", header[4])
	}

	totalLength := binary.BigEndian.Uint16(header[5:])
	if _, err := io.CopyN(io.Discard, conn, int64(totalLength)); err != nil {
		return fail(ctx, ErrIO, "discard AUTH_CHALLENGE body failed", err)
	}
	logger(ctx).Debug().Uint16("len", totalLength).Msg("AUTH_CHALLENGE discarded")
	return nil
}

func negotiateVersion(ctx context.Context, r io.Reader, w io.Writer) (uint16, error) {
	versionsCell := &cells.VersionCell{
		CircuitID: 0,
		Versions:  []uint16{4, 5},
	}

	if _, err := w.Write(versionsCell.Serialize()); err != nil {
		return 0, fail(ctx, ErrIO, "write VERSIONS failed", err)
	}

	initialBuffer := make([]byte, 5)
	n, err := r.Read(initialBuffer)
	if err != nil {
		return 0, fail(ctx, ErrIO, "read VERSIONS header failed", err)
	}
	if n != 5 {
		return 0, fail(ctx, ErrProtocolViolation, "short VERSIONS header", nil)
	}

	if uint8(initialBuffer[2]) != cells.COMMAND_VERSIONS {
		logger(ctx).Error().
			Uint8("expected", cells.COMMAND_VERSIONS).
			Uint8("got", initialBuffer[2]).
			Msg("invalid VERSIONS command")
		return 0, Publicf(ErrVersion, "expected VERSIONS, got command %d", initialBuffer[2])
	}

	length := binary.BigEndian.Uint16(initialBuffer[3:5])
	versions := make([]byte, 5+length)
	if _, err := io.ReadFull(r, versions[5:]); err != nil {
		return 0, fail(ctx, ErrIO, "read VERSIONS body failed", err)
	}
	copy(versions, initialBuffer)

	serverVersions, err := cells.UnserializeVersionCell(versions)
	if err != nil {
		return 0, fail(ctx, ErrVersion, "parse VERSIONS failed", err)
	}

	if slices.Contains(serverVersions.Versions, 5) {
		return 5, nil
	}
	if slices.Contains(serverVersions.Versions, 4) {
		return 4, nil
	}

	logger(ctx).Error().Uints16("server_versions", serverVersions.Versions).Msg("no common link version")
	return 0, Public(ErrVersion, "no common link version")
}
