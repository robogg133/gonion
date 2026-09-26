package crypto

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"time"
)

const CERT_KEY_TYPE_ED25519 uint8 = 1

type extension struct {
	Flag uint8
	Data []byte
}

type TorCert struct {
	ExpirationDate uint32
	CertType       uint8
	CertKeyType    uint8
	CertifiedKey   []byte
	Extensions     map[uint8]extension
	Signature      []byte
	rawCertificate []byte
}

func ParseIdentityVSigningCert(b []byte) (*TorCert, error) {
	if len(b) < 104 || len(b) > 65535 || b[0] != 1 {
		return nil, fmt.Errorf("certificate: invalid length or version")
	}
	b = bytes.Clone(b)
	cert := &TorCert{CertType: b[1], ExpirationDate: binary.BigEndian.Uint32(b[2:6]), CertKeyType: b[6], CertifiedKey: b[7:39], Extensions: make(map[uint8]extension), rawCertificate: b}
	end, offset := len(b)-64, 40
	for i := 0; i < int(b[39]); i++ {
		if end-offset < 4 {
			return nil, fmt.Errorf("certificate: truncated extension header")
		}
		n := int(binary.BigEndian.Uint16(b[offset:]))
		kind, flags := b[offset+2], b[offset+3]
		offset += 4
		if n > end-offset {
			return nil, fmt.Errorf("certificate: truncated extension")
		}
		if _, exists := cert.Extensions[kind]; exists {
			return nil, fmt.Errorf("certificate: duplicate extension")
		}
		if kind == 4 && n != 32 || kind != 4 && flags&1 != 0 {
			return nil, fmt.Errorf("certificate: invalid or unsupported critical extension")
		}
		cert.Extensions[kind] = extension{flags, b[offset : offset+n]}
		offset += n
	}
	if offset != end {
		return nil, fmt.Errorf("certificate: trailing bytes before signature")
	}
	cert.Signature = b[end:]
	return cert, nil
}

func VerifyConnection(cert4, cert5 *TorCert, tlsCert []byte) error {
	if cert4 == nil || cert5 == nil || cert4.CertType != 4 || cert5.CertType != 5 || cert4.CertKeyType != 1 || cert5.CertKeyType != 3 {
		return fmt.Errorf("certificate: missing or incorrect link certificate types")
	}
	key := cert4.Extensions[4].Data
	if err := verifyEdCertificate(cert4, key, time.Now()); err != nil {
		return err
	}
	if err := verifyEdCertificate(cert5, cert4.CertifiedKey, time.Now()); err != nil {
		return err
	}
	digest := sha256.Sum256(tlsCert)
	if !bytes.Equal(cert5.CertifiedKey, digest[:]) {
		return fmt.Errorf("certificate: TLS certificate digest mismatch")
	}
	return nil
}

func verifyEdCertificate(cert *TorCert, key []byte, now time.Time) error {
	if cert == nil || len(key) != 32 || len(cert.rawCertificate) < 104 || len(cert.Signature) != 64 || !now.Before(time.Unix(int64(cert.ExpirationDate)*3600, 0)) {
		return fmt.Errorf("certificate: incomplete or expired Ed25519 certificate")
	}
	if ext, ok := cert.Extensions[4]; ok && !bytes.Equal(ext.Data, key) {
		return fmt.Errorf("certificate: signing-key extension mismatch")
	}
	if !ed25519.Verify(key, cert.rawCertificate[:len(cert.rawCertificate)-64], cert.Signature) {
		return fmt.Errorf("certificate: invalid Ed25519 signature")
	}
	return nil
}

// VerifyRelayCertificates validates the full modern CERTS chain (tor-spec 4.2).
// The caller must additionally match these identities against its selected relay.
func VerifyRelayCertificates(certs map[uint8][]byte, tlsCert []byte) ([20]byte, [32]byte, error) {
	var rsaID [20]byte
	var edID [32]byte
	c4, err := ParseIdentityVSigningCert(certs[4])
	if err != nil {
		return rsaID, edID, err
	}
	c5, err := ParseIdentityVSigningCert(certs[5])
	if err != nil {
		return rsaID, edID, err
	}
	if err := VerifyConnection(c4, c5, tlsCert); err != nil {
		return rsaID, edID, err
	}
	copy(edID[:], c4.Extensions[4].Data)
	id, err := x509.ParseCertificate(certs[2])
	if err != nil {
		return rsaID, edID, fmt.Errorf("certificate: invalid RSA identity: %w", err)
	}
	now := time.Now()
	key, ok := id.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 1024 || now.Before(id.NotBefore) || !now.Before(id.NotAfter) {
		return rsaID, edID, fmt.Errorf("certificate: invalid RSA identity key or lifetime")
	}
	// Tor's historical self-signed identity certificates may use SHA-1. This is
	// protocol identity verification, not a relaxation of application Web PKI.
	var hash crypto.Hash
	switch id.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		hash = crypto.SHA1
	case x509.SHA256WithRSA:
		hash = crypto.SHA256
	case x509.SHA384WithRSA:
		hash = crypto.SHA384
	case x509.SHA512WithRSA:
		hash = crypto.SHA512
	default:
		return rsaID, edID, fmt.Errorf("certificate: unsupported RSA identity signature")
	}
	h := hash.New()
	h.Write(id.RawTBSCertificate)
	if rsa.VerifyPKCS1v15(key, hash, h.Sum(nil), id.Signature) != nil {
		return rsaID, edID, fmt.Errorf("certificate: invalid RSA identity self-signature")
	}
	cross := certs[7]
	if len(cross) < 37 || len(cross) != 37+int(cross[36]) || !bytes.Equal(cross[:32], edID[:]) || !now.Before(time.Unix(int64(binary.BigEndian.Uint32(cross[32:36]))*3600, 0)) {
		return rsaID, edID, fmt.Errorf("certificate: invalid RSA to Ed25519 cross-certificate")
	}
	digest := sha256.Sum256(append([]byte("Tor TLS RSA/Ed25519 cross-certificate"), cross[:36]...))
	if rsa.VerifyPKCS1v15(key, 0, digest[:], cross[37:]) != nil {
		return rsaID, edID, fmt.Errorf("certificate: invalid cross-certificate signature")
	}
	rsaID = sha1.Sum(x509.MarshalPKCS1PublicKey(key))
	return rsaID, edID, nil
}
