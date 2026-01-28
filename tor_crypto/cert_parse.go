package tor_crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	CERT_KEY_TYPE_ED25519 uint8 = 1
)

type extension struct {
	Flag uint8
	Data []byte
}

type TorCert struct {
	ExpirationDate uint32

	CertType uint8

	CertKeyType  uint8
	CertifiedKey []byte

	Extensions map[uint8]extension

	Signature []byte

	rawCertificate []byte
}

func ParseIdentityVSigningCert(b []byte) (*TorCert, error) {

	var cert TorCert
	cert.rawCertificate = b

	if b[0] != 1 {
		return nil, fmt.Errorf("invalid version")
	}

	cert.CertType = b[1]

	cert.ExpirationDate = binary.BigEndian.Uint32(b[2:6])

	cert.CertKeyType = b[6]
	cert.CertifiedKey = b[7:39] // 32 + 7 = 39

	cert.Extensions = make(map[uint8]extension)

	reader := bytes.NewReader(b[40:])
	for _ = range b[39] {
		parseCertExtension(reader, &cert.Extensions)
	}

	var err error
	cert.Signature, err = io.ReadAll(reader)

	return &cert, err
}

func parseCertExtension(reader *bytes.Reader, extensions *map[uint8]extension) error {
	extLenBlob := make([]byte, 2)
	reader.Read(extLenBlob)

	extLen := binary.BigEndian.Uint16(extLenBlob)

	extType, err := reader.ReadByte()
	if err != nil {
		return err
	}
	tmp := *extensions

	if _, exists := tmp[extType]; exists {
		return nil
	}

	var a extension
	a.Flag, err = reader.ReadByte()
	if err != nil {
		return err
	}

	buffer := make([]byte, extLen)
	reader.Read(buffer)
	a.Data = buffer

	tmp[extType] = a

	return nil
}
