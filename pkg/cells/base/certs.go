package cells

import (
	"encoding/binary"
	"fmt"
	"io"
)

const COMMAND_CERTS uint8 = 129

const (
	CERTS_TLS_LINK_X509           = 1
	CERTS_RSA_ID_X509             = 2
	CERTS_IDENTITY_V_SIGNING_CERT = 4
	CERTS_SIGNING_V_TLS_CERT      = 5
	CERTS_RSA_ID_V_IDENTITY       = 7
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

// Decode consumes the bounded CERTS payload, not its link-length prefix.
func (c *CertsCell) Decode(r io.Reader) error {
	if c.CircID != 0 {
		return ErrInvalidCircID
	}
	var count [1]byte
	if _, err := io.ReadFull(r, count[:]); err != nil {
		return err
	}
	c.Certificates = nil
	seen := [256]bool{}
	for i := 0; i < int(count[0]); i++ {
		var header [3]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return err
		}
		if seen[header[0]] {
			return fmt.Errorf("duplicate certificate type %d", header[0])
		}
		seen[header[0]] = true
		data := make([]byte, int(binary.BigEndian.Uint16(header[1:])))
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		c.Certificates = append(c.Certificates, certificate{header[0], data})
	}
	// tor-spec 4.2 permits trailing padding.
	return nil
}

func (c *CertsCell) Encode(w io.Writer) error {
	if c.CircID != 0 || len(c.Certificates) > 255 {
		return fmt.Errorf("invalid CERTS cell")
	}
	if _, err := w.Write([]byte{byte(len(c.Certificates))}); err != nil {
		return err
	}
	seen := [256]bool{}
	for _, cert := range c.Certificates {
		if seen[cert.Type] || len(cert.Cert) > 65535 {
			return fmt.Errorf("invalid or duplicate certificate")
		}
		seen[cert.Type] = true
		var header [3]byte
		header[0] = cert.Type
		binary.BigEndian.PutUint16(header[1:], uint16(len(cert.Cert)))
		if _, err := w.Write(header[:]); err != nil {
			return err
		}
		if _, err := w.Write(cert.Cert); err != nil {
			return err
		}
	}
	return nil
}
