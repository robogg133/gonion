package cells

import (
	"bytes"
	"encoding/binary"
	"io"
)

const COMMAND_CERTS uint8 = 129

const (
	CERTS_TLS_LINK_X509 = 1
	CERTS_RSA_ID_X509   = 2

	CERTS_IDENTITY_V_SIGNING_CERT = 4
	CERTS_SIGNING_V_TLS_CERT      = 5

	CERTS_RSA_ID_V_IDENTITY = 7
)

type certificate struct {
	Type uint8
	Cert []byte
}

type CertsCell struct {
	CircID       uint32
	Certificates []certificate
}

func (*CertsCell) ID() uint8               { return COMMAND_CERTS }
func (c *CertsCell) GetCircuitID() uint32  { return c.CircID }
func (c *CertsCell) SetCircuitID(n uint32) { c.CircID = n }

func (c *CertsCell) Decode(r io.Reader) error {

	if c.CircID != 0 {
		return ErrInvalidCircID
	}

	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}

	buffer := make([]byte, length)
	if _, err := io.ReadFull(r, buffer); err != nil {
		return err
	}

	certAmmount := buffer[0]

	offset := 1
	for range certAmmount {
		cert, n := readCertficate(bytes.NewReader(buffer[offset:]))
		offset += n

		if cert != nil {
			c.Certificates = append(c.Certificates, *cert)
		}
	}

	return nil
}

func (*CertsCell) Encode(io.Writer) error { return nil }

// readCertificate reads from reader, return certificate and ammount of readed bytes
func readCertficate(reader *bytes.Reader) (*certificate, int) {

	var n int

	certType, _ := reader.ReadByte()
	n++

	certLenghtBlob := make([]byte, 2)
	reader.Read(certLenghtBlob)
	n += 2

	certLength := binary.BigEndian.Uint16(certLenghtBlob)
	certLenghtBlob = nil

	if uint8(certType) != 1 && uint8(certType) != 2 && uint8(certType) != 4 && uint8(certType) != 5 && uint8(certType) != 7 {
		return nil, n + int(certLength)
	}

	cert := make([]byte, certLength)
	reader.Read(cert)
	n += int(certLength)

	return &certificate{
		Type: uint8(certType),
		Cert: cert,
	}, n
}
