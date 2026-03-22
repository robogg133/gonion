package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
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

func VerifyConnection(cert4, cert5 *TorCert, tlsCert []byte) error {
	// Verifying certificate 4

	if time.Unix(int64(cert4.ExpirationDate)*3600, 0).Before(time.Now()) {
		return fmt.Errorf("invalid certificate 4 from server: expired")
	}

	dataToCheck := cert4.rawCertificate[:len(cert4.rawCertificate)-64]

	key := ed25519.PublicKey(cert4.Extensions[4].Data)

	if !ed25519.Verify(key, dataToCheck, cert4.Signature) {
		return fmt.Errorf("invalid certificate 4 from server: public key don't match the signature")
	}

	// Verifying certificate 5
	//
	if time.Unix(int64(cert5.ExpirationDate)*3600, 0).Before(time.Now()) {
		return fmt.Errorf("invalid certificate 5 from server: expired")
	}

	dataToCheck = cert5.rawCertificate[:len(cert5.rawCertificate)-64]

	key = ed25519.PublicKey(cert4.CertifiedKey)

	if !ed25519.Verify(key, dataToCheck, cert5.Signature) {
		return fmt.Errorf("invalid certificate 5 from server: public key from cert 4 don't match the signature")
	}

	// Verifying TLS Certificate

	digestCertificate := sha256.Sum256(tlsCert)
	if !bytes.Equal(cert5.CertifiedKey, digestCertificate[:]) {
		return fmt.Errorf("invalid certificates from server: TLS cert don't match with digest from cert 5")
	}

	return nil
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
	for range b[39] {
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
