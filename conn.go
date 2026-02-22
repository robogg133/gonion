package gonion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/relay"
	"github.com/robogg133/gonion/tor_crypto"
)

const CONNECTION_TIMEOUT = 60 * time.Second

type Conn struct {
	socket         net.Conn
	circuits       map[uint32]*Circuit
	ProtcolVersion uint16

	netInfo cells.NetInfoCell

	Cert *x509.Certificate

	userDataPipeWriter *io.PipeWriter
	userDataPipeReader *io.PipeReader

	mu sync.RWMutex

	writeCall chan []byte
	closeCh   chan struct{}

	guardID uint32
	exitID  uint32
}

func NewConn(addr string) (*Conn, error) {

	var conn Conn
	conn.writeCall = make(chan []byte)
	conn.closeCh = make(chan struct{})
	conn.circuits = make(map[uint32]*Circuit)

	var err error
	conn.socket, conn.Cert, err = setupTls(addr)
	if err != nil {
		return nil, err
	}

	conn.ProtcolVersion, err = negotiateVersion(conn.socket, conn.socket)
	if err != nil {
		return nil, err
	}

	constructor := cells.NewCellTranslator(cells.AllKnownCells, relay.RelayCellConstructor{})

	pkg, err := constructor.ReadCell(conn.socket)
	if err != nil {
		return nil, err
	}
	if pkg.ID() != cells.COMMAND_CERTS {
		return nil, fmt.Errorf("protocol violation: incorrect package order")
	}

	certs := pkg.(*cells.CertsCell)

	var cert4 *tor_crypto.TorCert
	var cert5 *tor_crypto.TorCert
	for _, v := range certs.Certificates {
		if v.Type == 4 {
			cert4, err = tor_crypto.ParseIdentityVSigningCert(v.Cert)
			if err != nil {
				return nil, err
			}
		} else if v.Type == 5 {
			cert5, err = tor_crypto.ParseIdentityVSigningCert(v.Cert)
			if err != nil {
				return nil, err
			}
		}
	}
	if err := tor_crypto.VerifyConnection(cert4, cert5, conn.Cert.Raw); err != nil {
		return nil, err
	}

	if err := discardAuthChallange(conn.socket); err != nil {
		return nil, err
	}

	pkg, err = constructor.ReadCell(conn.socket)
	if err != nil {
		return nil, err
	}
	if pkg.ID() != cells.COMMAND_NETINFO {
		return nil, fmt.Errorf("protocol violation: incorrect package order")
	}

	netinfo := pkg.(*cells.NetInfoCell)
	conn.netInfo = *netinfo

	info := cells.NetInfoCell{
		CircuitID: 0,
		Timestamp: 0,
		OtherAddr: netip.MustParseAddrPort(conn.socket.RemoteAddr().String()).Addr(),
		MyAdress:  nil,
	}
	if err := constructor.WriteCell(&info, conn.socket); err != nil {
		return nil, err
	}
	if err := conn.socket.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	go conn.readLoop()
	go conn.writeLoop()

	return &conn, nil
}

func setupTls(addr string) (net.Conn, *x509.Certificate, error) {

	ctx, cancel := context.WithTimeout(context.Background(), CONNECTION_TIMEOUT)
	defer cancel()

	dialer := &tls.Dialer{
		Config: &tls.Config{

			InsecureSkipVerify: true,

			// Adding tor cipher suites
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			// Disabling session resumption
			SessionTicketsDisabled: true,
			ClientSessionCache:     nil,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, nil, err
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, err
	}

	state := tlsConn.ConnectionState()

	certificate := state.PeerCertificates[0]

	return tlsConn, certificate, nil
}

func discardAuthChallange(conn net.Conn) error {

	header := make([]byte, 7)
	conn.Read(header)

	if uint8(header[4]) != cells.COMMAND_AUTH_CHALLANGE {
		return fmt.Errorf("invalid auth_challange (%d) cell: invalid command: %d", cells.COMMAND_AUTH_CHALLANGE, uint8(header[4]))
	}

	totalLenght := binary.BigEndian.Uint16(header[5:])
	_, err := io.CopyN(io.Discard, conn, int64(totalLenght))

	return err
}
