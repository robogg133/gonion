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
	"slices"
	"sync"
	"time"

	cells "git.servidordomal.fun/robogg133/gonion/pkg/cells/base"
	"git.servidordomal.fun/robogg133/gonion/pkg/cells/relay"
	"git.servidordomal.fun/robogg133/gonion/pkg/crypto"
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
	closeCh   chan string

	guardID uint32
	exitID  uint32

	cellBodyLen int
}

func NewConn(c net.Conn) (*Conn, error) {

	conn := &Conn{
		writeCall: make(chan []byte, 256),
		closeCh:   make(chan string),
		circuits: &circuits{
			circs: make(map[uint32]*Circuit),
		},
		cellBodyLen: cells.CELL_BODY_LEN,
	}

	var err error
	conn.socket, conn.Cert, err = setupTls(c)
	if err != nil {
		return nil, err
	}

	conn.socket.SetDeadline(time.Now().Add(60 * time.Second))

	conn.ProtcolVersion, err = negotiateVersion(conn.socket, conn.socket)
	if err != nil {
		return nil, err
	}

	coder := cells.NewCellCoder(cells.AllKnownCells, &relay.RelayCellCoder{})

	pkg, err := coder.ReadCell(conn.socket)
	if err != nil {
		return nil, err
	}
	if pkg.ID() != cells.COMMAND_CERTS {
		return nil, fmt.Errorf("protocol violation: incorrect package order")
	}

	certs := pkg.(*cells.CertsCell)

	var cert4 *crypto.TorCert
	var cert5 *crypto.TorCert
	for _, v := range certs.Certificates {
		switch v.Type {

		case 4:
			cert4, err = crypto.ParseIdentityVSigningCert(v.Cert)
			if err != nil {
				return nil, err
			}
		case 5:
			cert5, err = crypto.ParseIdentityVSigningCert(v.Cert)
			if err != nil {
				return nil, err
			}

		}
	}
	if err := crypto.VerifyConnection(cert4, cert5, conn.Cert.Raw); err != nil {
		return nil, err
	}

	if err := discardAuthChallange(conn.socket); err != nil {
		return nil, err
	}

	pkg, err = coder.ReadCell(conn.socket)
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
	if err := coder.WriteCell(&info, conn.socket); err != nil {
		return nil, err
	}

	conn.socket.SetDeadline(time.Time{})

	go conn.readLoop()
	go conn.writeLoop()

	return conn, nil
}

func (conn *Conn) Close() error {
	return nil
}

func setupTls(c net.Conn) (net.Conn, *x509.Certificate, error) {

	ctx, cancel := context.WithTimeout(context.Background(), CONNECTION_TIMEOUT)
	defer cancel()

	tlsConn := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,

		// Adding tor cipher suites
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		// Disabling session resumption
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}

	state := tlsConn.ConnectionState()

	certificate := state.PeerCertificates[0]

	return tlsConn, certificate, nil
}

func discardAuthChallange(conn net.Conn) error {

	header := make([]byte, 7)
	io.ReadFull(conn, header)

	if uint8(header[4]) != cells.COMMAND_AUTH_CHALLANGE {
		return fmt.Errorf("invalid auth_challange (%d) cell: invalid command: %d", cells.COMMAND_AUTH_CHALLANGE, uint8(header[4]))
	}

	totalLenght := binary.BigEndian.Uint16(header[5:])
	_, err := io.CopyN(io.Discard, conn, int64(totalLenght))

	return err
}

func negotiateVersion(r io.Reader, w io.Writer) (uint16, error) {
	versionsCell := &cells.VersionCell{
		CircuitID: 0,
		Versions:  []uint16{4, 5},
	}

	w.Write(versionsCell.Serialize())

	initialBuffer := make([]byte, 5)
	n, err := r.Read(initialBuffer)
	if err != nil {
		return 0, err
	}
	if n != 5 {
		return 0, fmt.Errorf("did not read 5 bytes from connection")
	}

	if uint8(initialBuffer[2]) != cells.COMMAND_VERSIONS {
		return 0, fmt.Errorf("invalid version (%d) cell: invalid command: %d", cells.COMMAND_VERSIONS, uint8(initialBuffer[3]))
	}

	length := binary.BigEndian.Uint16(initialBuffer[3:5])

	versions := make([]byte, 5+length)
	if _, err := r.Read(versions[5:]); err != nil {
		return 0, err
	}

	copy(versions, initialBuffer)

	serverVersions, err := cells.UnserializeVersionCell(versions)
	if err != nil {
		return 0, err
	}

	if slices.Contains(serverVersions.Versions, 5) {
		return 5, nil
	} else if slices.Contains(serverVersions.Versions, 4) {
		return 4, nil
	}

	return 0, fmt.Errorf("no version match with server")
}
