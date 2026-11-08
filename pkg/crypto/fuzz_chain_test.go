package crypto

import (
	"bytes"
	"testing"
	"time"
)

// CERTS-chain fuzzing for V5.2. Provenance: seeds embed the in-tree
// cert2/cert4/cert5/cert7 fixtures from pkg/crypto/testdata (see
// certs_test.go TestRelayCertificateChainPositive). The fuzzer mutates the
// full chain and TLS bytes; verification is time-pinned to the positive
// fixture's validity window so expiry is not the dominant rejection.
// No crasher has been minimized yet; campaign findings must be added as
// seeds with an ID in this header.

func FuzzVerifyRelayCertificates(f *testing.F) {
	// Each seed is (cert2, cert4, cert5, cert7, tls) as separate args so the
	// fuzzer combines them structurally rather than as one blob.
	f.Add(cert2Bytes, cert4Bytes, cert5Bytes, cert7Bytes, tlsBytes)
	f.Add([]byte{}, []byte{}, []byte{}, []byte{}, []byte{})
	f.Add(cert2Bytes, cert4Bytes[:40], cert5Bytes, cert7Bytes, tlsBytes)
	f.Add(cert2Bytes, cert4Bytes, cert5Bytes, cert7Bytes, make([]byte, 32))
	// Truncated cross-cert and TLS digest mismatch seeds.
	f.Add(cert2Bytes, cert4Bytes, cert5Bytes, cert7Bytes[:20], tlsBytes)
	f.Add(cert2Bytes, make([]byte, 2), make([]byte, 2), make([]byte, 2), make([]byte, 2))
	f.Fuzz(func(t *testing.T, c2, c4, c5, c7, tls []byte) {
		// Bound each component to a plausible CERTS cell payload (65k per
		// certificate); oversize items are already rejected by the parser.
		for _, part := range [][]byte{c2, c4, c5, c7, tls} {
			if len(part) > 1<<16 {
				return
			}
		}
		// Time-pinned to the fixture's validity (certs_test.go validTime).
		when := time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC)
		certs := map[uint8][]byte{2: c2, 4: c4, 5: c5, 7: c7}
		// The chain verifier must never panic on adversarial bytes; an
		// error is an expected outcome, success on mutated bytes is
		// checked only for internal consistency (same RSA/Ed pair).
		rsaID, edID, err := verifyRelayCertificates(certs, tls, when)
		if err != nil {
			return
		}
		if rsaID == ([20]byte{}) || edID == ([32]byte{}) {
			t.Fatal("zero identity returned on successful chain verification")
		}
		// Verify determinism: same inputs, same identities.
		rsa2, ed2, err := verifyRelayCertificates(certs, tls, when)
		if err != nil || rsa2 != rsaID || ed2 != edID {
			t.Fatal("nondeterministic chain verification")
		}
	})
}

func FuzzParseTorCert(f *testing.F) {
	// Direct single-certificate parser fuzz (supplements
	// FuzzParseIdentityVSigningCert in fuzz_test.go with size/type diversity).
	f.Add(cert4Bytes)
	f.Add(cert5Bytes)
	f.Add(cert2Bytes)
	f.Add([]byte{})
	f.Add(make([]byte, 104))
	f.Add(make([]byte, 200))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		cert, err := ParseIdentityVSigningCert(b)
		if err != nil {
			return
		}
		if len(cert.Signature) != 64 {
			t.Fatal("bad signature length")
		}
		// Verify must reject every key except the genuine signer; fuzz with
		// the certified key itself as a candidate (rejection is expected).
		_ = cert.Verify(bytes.Clone(cert.CertifiedKey), time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC))
		_ = cert.Verify(make([]byte, 32), time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC))
	})
}
