package gonion

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/robogg133/gonion/internal/shared"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/crypto"
	"github.com/robogg133/gonion/pkg/storage"
)

const CONNECTION_TIMEOUT = 60 * time.Second

type cellWrite struct {
	data []byte
	done chan error // buffered: cancellation must not block the writer
}

type Conn struct {
	socket         net.Conn
	circuits       *circuits
	ProtcolVersion uint16

	netInfo cells.NetInfoCell

	Cert      *x509.Certificate
	relayRSA  [20]byte
	relayEd   [32]byte
	consensus *common.Consensus

	userDataPipeWriter *io.PipeWriter
	userDataPipeReader *io.PipeReader

	mu        sync.RWMutex
	publishMu sync.Mutex

	writeCall chan cellWrite
	ctx       context.Context
	ctxCancel context.CancelCauseFunc

	// closeOnce makes link teardown idempotent: every circuit is released and
	// the socket is closed at most once, whether the cause is Close or an I/O
	// error observed by either link loop.
	closeOnce sync.Once
	closeErr  error

	// circuit IDs are allocated and registered while holding circIDMu. The
	// reservation set covers the window between allocation (which needs the ID
	// for logging and the Circuit context) and registration.
	circIDMu    sync.Mutex
	circuitIDs  map[uint32]struct{}
	circIDRand  io.Reader
	maxCircuits int

	guardID uint32
	exitID  uint32

	cellBodyLen int

	storage storage.Storage

	recoveryMu     sync.Mutex
	recoveryCancel context.CancelFunc
	recoveryConn   *Conn
	// trustedAuthorities, when set, replaces the default nine public C Tor
	// authority pins for consensus authentication. It is set once, before
	// bootstrap fetches a consensus, and never mutated afterwards; recovery
	// connections copy it verbatim.
	trustedAuthorities [][20]byte
}

type ConnOption uint8

const (
	ConnOptionSkipRelayFingerprintCheck ConnOption = iota
)

// SetTrustedAuthorities replaces the default nine public C Tor authority pins
// with an explicit caller-supplied set (private or controlled networks). The
// set must be non-empty, unique and non-zeroed; consensus acceptance then
// requires a strict majority of these pins. Call it once, before the first
// consensus fetch: identity pins of relays and connection CERTS are separate
// checks and are never relaxed by this override.
func (c *Conn) SetTrustedAuthorities(pins [][20]byte) error {
	if c.trustedAuthorities != nil {
		return Public(ErrDirectory, "authority pins already set")
	}
	if len(pins) == 0 {
		return Public(ErrDirectory, "empty authority pin set")
	}
	seen := make(map[[20]byte]bool, len(pins))
	out := make([][20]byte, 0, len(pins))
	for _, id := range pins {
		if id == ([20]byte{}) {
			return Public(ErrDirectory, "invalid authority pin")
		}
		if seen[id] {
			return Public(ErrDirectory, "duplicate authority pin")
		}
		seen[id] = true
		out = append(out, id)
	}
	c.trustedAuthorities = out
	return nil
}

// SetStorage attaches a consensus store to the connection.
// When set, bootstrap and consensus refresh read from and write to it.
func (c *Conn) SetStorage(st storage.Storage) {
	c.storage = st
}

// NewConn performs the Tor link handshake on c.
// logOut receives structured logs when debug is false; when debug is true, logs go to stderr in console form.
func NewConn(c net.Conn, logOut io.Writer, debug bool, opts ...ConnOption) (*Conn, error) {
	if c == nil {
		return nil, Public(ErrIO, "nil OR connection")
	}
	success := false
	defer func() {
		if !success {
			_ = c.Close()
		}
	}()
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
		writeCall: make(chan cellWrite, maxQueuedLinkCells),
		ctx:       ctx,
		ctxCancel: cancel,
		circuits: &circuits{
			circs: make(map[uint32]*Circuit),
		},
		circuitIDs:  make(map[uint32]struct{}),
		circIDRand:  rand.Reader,
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
	certData := make(map[uint8][]byte)
	for _, v := range certs.Certificates {
		certData[v.Type] = v.Cert
	}
	conn.relayRSA, conn.relayEd, err = crypto.VerifyRelayCertificates(certData, conn.Cert.Raw)
	if err != nil {
		cancel(err)
		return nil, fail(ctx, ErrHandshake, "certificate verification failed", err)
	}
	if !slices.Contains(opts, ConnOptionSkipRelayFingerprintCheck) {
		if pinned, ok := c.(interface{ ExpectedRelayIdentity() [20]byte }); ok {
			if err := conn.CheckRelayFingerprint(pinned.ExpectedRelayIdentity()); err != nil {
				cancel(err)
				return nil, err
			}
		}
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
		OtherAddr: parseRemoteAddr(conn.socket.RemoteAddr()),
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

	success = true
	return conn, nil
}

// Consensus returns this connection's authenticated directory snapshot, not a
// process-global consensus that another embedded client can replace.
func (conn *Conn) Consensus() *common.Consensus {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	return conn.consensus.Clone()
}

// CheckRelayFingerprint matches the CERTS-authenticated RSA identity against
// a caller-selected fallback/bridge pin. Zero is never an identity wildcard.
func (conn *Conn) CheckRelayFingerprint(expected [20]byte) error {
	if expected == [20]byte{} || expected != conn.relayRSA {
		return Public(ErrHandshake, "relay identity does not match expected fingerprint")
	}
	return nil
}

func (conn *Conn) CheckRelayIdentity(relay *common.RouterStatus) error {
	if relay == nil || conn.CheckRelayFingerprint(relay.NodeID) != nil || len(relay.IdEd25519) != 32 || !slices.Equal(relay.IdEd25519, conn.relayEd[:]) {
		return Public(ErrHandshake, "relay identity does not match selected consensus relay")
	}
	return nil
}

func parseRemoteAddr(addr net.Addr) netip.Addr {
	if addr != nil {
		if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
			return ap.Addr()
		}
	}
	// Pluggable transports may not expose an IP endpoint. An unspecified IPv4
	// address still has the exact ATYPE/ALEN framing required by tor-spec 4.5;
	// an invalid netip.Addr would emit an IPv6 header without its 16-byte value.
	return netip.IPv4Unspecified()
}

func (conn *Conn) Close() error {
	logger(conn.ctx).Info().Msg("closing connection")
	conn.recoveryMu.Lock()
	cancel, replacement := conn.recoveryCancel, conn.recoveryConn
	conn.recoveryCancel, conn.recoveryConn = nil, nil
	conn.recoveryMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if replacement != nil {
		_ = replacement.Close()
	}
	// Best-effort DESTROY for established circuits is queued before the socket
	// is closed. There is no acknowledgement wait.
	conn.shutdown(ErrClosed, true)
	return conn.closeErr
}

// fail records a terminal link error: every owned circuit is torn down and the
// underlying socket is closed so blocked readers and writers cannot survive.
func (conn *Conn) fail(cause error) {
	conn.shutdown(cause, false)
}

func (conn *Conn) shutdown(cause error, notifyPeer bool) {
	if cause == nil {
		cause = ErrClosed
	}
	conn.closeOnce.Do(func() {
		shutdownCircuits := func() {
			for _, circuit := range conn.circuitSnapshot() {
				circuit.teardown(cause, destroyReasonFor(cause), notifyPeer)
			}
		}
		if notifyPeer {
			// Queue best-effort DESTROY while the writer still exists.
			shutdownCircuits()
			if conn.ctxCancel != nil {
				conn.ctxCancel(cause)
			}
		} else {
			// On I/O failure, cancel ownership first so no observer sees a dead
			// link with a still-live connection context.
			if conn.ctxCancel != nil {
				conn.ctxCancel(cause)
			}
			shutdownCircuits()
		}
		if conn.socket != nil {
			conn.closeErr = conn.socket.Close()
		}
	})
}

func (conn *Conn) circuitSnapshot() []*Circuit {
	if conn.circuits == nil {
		return nil
	}
	conn.circuits.mu.RLock()
	defer conn.circuits.mu.RUnlock()
	out := make([]*Circuit, 0, len(conn.circuits.circs))
	for _, circuit := range conn.circuits.circs {
		out = append(out, circuit)
	}
	return out
}

func (conn *Conn) Context() context.Context {
	return conn.ctx
}

// circuitLimit is the per-connection ceiling. A non-positive field selects the
// package default, so manually built Conns keep the production ceiling.
func (conn *Conn) circuitLimit() int {
	if conn.maxCircuits > 0 {
		return conn.maxCircuits
	}
	return MaxCircuitsPerConn
}

// allocCircID reserves a random, nonzero, collision-checked CircID. The connection
// is the only allocator: occupancy is checked against the registry and the
// per-connection reservation set under circIDMu.
func (conn *Conn) allocCircID() (uint32, error) {
	conn.circIDMu.Lock()
	defer conn.circIDMu.Unlock()
	if conn.circuitIDs == nil {
		conn.circuitIDs = make(map[uint32]struct{})
	}
	source := conn.circIDRand
	if source == nil {
		source = rand.Reader
	}
	version := conn.ProtcolVersion
	if version == 0 {
		// Manually assembled Conns have no negotiated version; production links
		// always expose 4 or 5 here.
		version = 4
	}
	for attempt := 0; attempt < shared.CIRCUIT_ID_MAX_RETRIES; attempt++ {
		id, err := shared.RandomCircID(source, version)
		if err != nil {
			if conn.ctx != nil {
				return 0, fail(conn.ctx, ErrCircuit, "circuit id generation failed", err)
			}
			return 0, Public(ErrCircuit, "circuit id generation failed")
		}
		if id == 0 {
			continue
		}
		if conn.circuits != nil && conn.circuits.Get(id) != nil {
			continue
		}
		if _, reserved := conn.circuitIDs[id]; reserved {
			continue
		}
		conn.circuitIDs[id] = struct{}{}
		return id, nil
	}
	return 0, &CircuitIDExhaustedError{Attempts: shared.CIRCUIT_ID_MAX_RETRIES}
}

// registerCircuit moves a reserved ID into the live registry without replacing
// an existing entry. A registry collision leaves the existing circuit intact.
func (conn *Conn) registerCircuit(circuit *Circuit) error {
	conn.circIDMu.Lock()
	defer conn.circIDMu.Unlock()
	if conn.circuits == nil {
		delete(conn.circuitIDs, circuit.ID)
		return Public(ErrCircuit, "connection has no circuit registry")
	}
	if conn.ctx != nil && conn.ctx.Err() != nil {
		delete(conn.circuitIDs, circuit.ID)
		return Public(ErrClosed, "connection is closed")
	}
	if conn.circuits.Len() >= conn.circuitLimit() {
		delete(conn.circuitIDs, circuit.ID)
		return &CircuitLimitError{Limit: conn.circuitLimit()}
	}
	if !conn.circuits.Add(circuit.ID, circuit) {
		delete(conn.circuitIDs, circuit.ID)
		return &CircuitIDExhaustedError{Attempts: shared.CIRCUIT_ID_MAX_RETRIES}
	}
	delete(conn.circuitIDs, circuit.ID)
	return nil
}

// sendDestroy queues a link-layer DESTROY best effort and never waits for the
// write. A full or closed outbound queue is intentionally not fatal here.
func (conn *Conn) sendDestroy(id uint32, reason uint8) {
	if conn == nil || conn.writeCall == nil {
		return
	}
	coder := cells.NewCellCoder(cells.AllKnownCells)
	raw, err := coder.MarshalCell(&cells.DestroyCell{CircuitID: id, Reason: reason})
	if err != nil {
		return
	}
	done := make(chan error, 1)
	select {
	case conn.writeCall <- cellWrite{data: raw, done: done}:
	default:
	}
}

// Add registers a circuit only when the ID is free. It never replaces a live
// entry, so a late teardown cannot hide a newer circuit using the same ID.
func (m *circuits) Add(id uint32, value *Circuit) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.circs == nil {
		m.circs = make(map[uint32]*Circuit)
	}
	if _, exists := m.circs[id]; exists {
		return false
	}
	m.circs[id] = value
	return true
}

// DeleteIf removes id only while it still maps to the exact circuit value.
func (m *circuits) DeleteIf(id uint32, value *Circuit) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.circs[id]; !ok || current != value {
		return false
	}
	delete(m.circs, id)
	return true
}

func (m *circuits) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.circs)
}

func (m *streams) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

func (m *streams) snapshot() []*Stream {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Stream, 0, len(m.streams))
	for _, stream := range m.streams {
		out = append(out, stream)
	}
	return out
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
	n, err := io.ReadFull(r, initialBuffer)
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

	length := int(binary.BigEndian.Uint16(initialBuffer[3:5]))
	if initialBuffer[0] != 0 || initialBuffer[1] != 0 || length == 0 || length%2 != 0 {
		return 0, Public(ErrVersion, "invalid VERSIONS circuit ID or payload length")
	}
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
