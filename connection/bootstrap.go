package connection

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/tor_crypto"
)

const CONNECTION_TIMEOUT = 60 * time.Second

type TORConnection struct {
	ProtocolVersion uint16

	CircuitID      uint32
	CircuitID_HOP2 uint32
	CircuitID_HOP3 uint32

	ServerCertificate x509.Certificate
	NetInfo           cells.NetInfoCell

	ForwardDigest   hash.Hash
	BackWardsDigest hash.Hash

	KeyForwardAES128CTR   cipher.Stream
	KeyBackwardsAES128CTR cipher.Stream

	CircuitChannelPackets uint8

	Translator cells.CellTranslator

	RelayStreamID uint16

	Conn net.Conn
}

func CreateConnection(ip string, port uint16) (*TORConnection, error) {
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

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, err
	}

	if err := tlsConn.Handshake(); err != nil {
		panic(err)
	}

	state := tlsConn.ConnectionState()

	certificate := state.PeerCertificates[0]
	return &TORConnection{
		Conn:              conn,
		ServerCertificate: *certificate,
	}, err
}

func (t *TORConnection) NegotiateVersion() error {
	versionsCell := &cells.VersionCell{
		CircuitID: 0,
		Versions:  []uint16{4, 5},
	}

	t.Conn.Write(versionsCell.Serialize())

	initialBuffer := make([]byte, 5)
	n, err := t.Conn.Read(initialBuffer)
	if err != nil {
		return err
	}
	if n != 5 {
		return fmt.Errorf("did not read 5 bytes from connection")
	}

	if uint8(initialBuffer[2]) != cells.COMMAND_VERSIONS {
		return fmt.Errorf("invalid version (%d) cell: invalid command: %d", cells.COMMAND_VERSIONS, uint8(initialBuffer[3]))
	}

	length := binary.BigEndian.Uint16(initialBuffer[3:5])

	versions := make([]byte, 5+length)
	if _, err := t.Conn.Read(versions[5:]); err != nil {
		return err
	}

	copy(versions, initialBuffer)

	serverVersions, err := cells.UnserializeVersionCell(versions)
	if err != nil {
		return err
	}

	if slices.Contains(serverVersions.Versions, 5) {
		t.ProtocolVersion = 5
		return nil
	} else if slices.Contains(serverVersions.Versions, 4) {
		t.ProtocolVersion = 4
		return nil
	}

	return fmt.Errorf("no version match with server")
}

func (t *TORConnection) GetCerts() (*cells.CertsCell, error) {

	t.Translator = cells.NewCellTranslator(t.Conn, t.Conn, 4, cells.AllKnownCells)

	c, err := t.Translator.ReadCell()
	if err != nil {
		return nil, err
	}

	return c.(*cells.CertsCell), err
}

func (t *TORConnection) ReadAuthChallange() error {

	header := make([]byte, 7)
	t.Conn.Read(header)

	if uint8(header[4]) != cells.COMMAND_AUTH_CHALLANGE {
		return fmt.Errorf("invalid auth_challange (%d) cell: invalid command: %d", cells.COMMAND_AUTH_CHALLANGE, uint8(header[4]))
	}

	totalLenght := binary.BigEndian.Uint16(header[5:])
	_, err := io.CopyN(io.Discard, t.Conn, int64(totalLenght))

	return err
}

func (t *TORConnection) ReadNetInfo() (*cells.NetInfoCell, error) {

	c, err := t.Translator.ReadCell()
	if err != nil {
		return nil, err
	}

	return c.(*cells.NetInfoCell), nil
}

func (t *TORConnection) SendNetInfo() error {

	addr, err := netip.ParseAddrPort(t.Conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	a := cells.NetInfoCell{
		Timestamp: 0,
		OtherAddr: addr.Addr(),
		MyAdress:  []netip.Addr{},
	}

	return t.Translator.WriteCell(&a)
}

func OpenConnection(ip string, orport uint16) (*TORConnection, error) {

	torConn, err := CreateConnection(ip, orport)
	if err != nil {
		return nil, err
	}

	if err := torConn.NegotiateVersion(); err != nil {
		return nil, err
	}
	certs, err := torConn.GetCerts()
	if err != nil {
		return nil, err
	}

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
	if err := tor_crypto.VerifyConnection(cert4, cert5, torConn.ServerCertificate.Raw); err != nil {
		return nil, err
	}

	if err := torConn.ReadAuthChallange(); err != nil {
		return nil, err
	}
	ptr, err := torConn.ReadNetInfo()
	if err != nil {
		return nil, err
	}
	torConn.NetInfo = *ptr

	return torConn, torConn.SendNetInfo()
}
