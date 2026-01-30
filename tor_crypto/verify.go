package tor_crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"
)

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
