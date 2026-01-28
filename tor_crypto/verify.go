package tor_crypto

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

func (cert *TorCert) VerifyCert() error {

	switch cert.CertType {
	case 4:
		dataToCheck := cert.rawCertificate[:len(cert.rawCertificate)-64]

		key := ed25519.PublicKey(cert.Extensions[4].Data)

		if !ed25519.Verify(key, dataToCheck, cert.Signature) {
			return fmt.Errorf("invalid certificate from server")
		}

	}

	if time.Unix(int64(cert.ExpirationDate)*3600, 0).Before(time.Now()) {
		return fmt.Errorf("invalid certificate from server: expired")
	}

	return nil
}

func VerifyConnection(cert4, cert5 TorCert, tlsCert []byte) error {
	// need to impelement
	return nil
}
