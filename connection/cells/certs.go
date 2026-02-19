package cells

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	CircuitID    uint32
	Certificates []certificate
}

func (*CertsCell) ID() uint8 { return COMMAND_CERTS }

func (c *CertsCell) Decode(r io.Reader) error {

	length := make([]byte, 2)
	if _, err := io.ReadFull(r, length); err != nil {
		return err
	}

	totalLenght := binary.BigEndian.Uint16(length)

	buffer := make([]byte, totalLenght)
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

func UnserializeCertsCell(b []byte) (*CertsCell, error) {

	var cell CertsCell

	cell.CircuitID = binary.BigEndian.Uint32(b[0:4])
	if cell.CircuitID != 0 {
		return nil, fmt.Errorf("circuitID is not 0, circuitID : %d", cell.CircuitID)
	}
	if uint8(b[4]) != COMMAND_CERTS {
		return nil, fmt.Errorf("invalid certs cell: invalid command: %d", uint8(b[4]))
	}

	certAmmount := uint8(b[7])

	offset := 8
	for range certAmmount {
		cert, n := readCertficate(bytes.NewReader(b[offset:]))
		offset += n

		if cert != nil {
			cell.Certificates = append(cell.Certificates, *cert)
		}
	}

	return &cell, nil
}

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
