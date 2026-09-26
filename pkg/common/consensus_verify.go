package common

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// DefaultAuthorities returns the v3 RSA authority identities in C Tor's
// src/app/config/auth_dirs.inc (3937194). These are NOT relay fingerprints.
func DefaultAuthorities() [][20]byte {
	ids := []string{
		"F533C81CEF0BC0267857C99B2F471ADF249FA232", "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
		"E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", "ED03BB616EB2F60BEC80151114BB25CEF515B226",
		"0232AF901C31A04EE9848595AF9BB7620D4C5B2E", "49015F787433103580E3B66A1707A00E60F2D15B",
		"23D15D965BC35114467363C165C4F724B64B4F66", "27102BC123E7AF1D4741AE047E160C91ADC76B21",
		"70849B868D606BAECFB6128C5E3D782029AA394F",
	}
	out := make([][20]byte, len(ids))
	for i, s := range ids {
		b, _ := hex.DecodeString(s)
		copy(out[i][:], b)
	}
	return out
}

type authorityCertificate struct {
	identity, signingDigest [20]byte
	signingKey              *rsa.PublicKey
	published, expires      time.Time
}

// AuthenticateConsensus reparses signed bytes rather than trusting a cached
// model. Certificates are untrusted input; only pinned, currently valid keys
// with both signatures verified may count toward a strict authority majority.
func AuthenticateConsensus(raw, certificates []byte, trusted [][20]byte, now time.Time) (*Consensus, error) {
	c, err := ParseConsensus(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if !c.IsLive(now) {
		return nil, fmt.Errorf("consensus: document is not currently valid")
	}
	pins := make(map[[20]byte]bool, len(trusted))
	for _, id := range trusted {
		if id == [20]byte{} || pins[id] {
			return nil, fmt.Errorf("consensus: invalid or duplicate authority pin")
		}
		pins[id] = true
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("consensus: no trusted authorities")
	}
	certs, err := parseAuthorityCertificates(certificates, now)
	if err != nil {
		return nil, err
	}
	marker := []byte("\ndirectory-signature ")
	start := bytes.Index(raw, marker)
	if start < 0 {
		return nil, fmt.Errorf("consensus: missing signature boundary")
	}
	signed := raw[:start+len(marker)]
	d1, d256 := sha1.Sum(signed), sha256.Sum256(signed)
	good := make(map[[20]byte]bool)
	remaining := raw[start+1:]
	for len(bytes.TrimSpace(remaining)) > 0 {
		line, rest, ok := bytes.Cut(remaining, []byte{'\n'})
		if !ok {
			return nil, fmt.Errorf("consensus: truncated signature header")
		}
		f := strings.Fields(string(line))
		if len(f) < 3 || f[0] != "directory-signature" {
			return nil, fmt.Errorf("consensus: unexpected data in signature section")
		}
		algorithm, offset := "sha1", 1
		if len(f) >= 4 {
			algorithm, offset = f[1], 2
		}
		id, e1 := directoryDigest(f[offset])
		keyID, e2 := directoryDigest(f[offset+1])
		block, next, err := directoryPEM(rest, "SIGNATURE")
		if err != nil || e1 != nil || e2 != nil {
			return nil, fmt.Errorf("consensus: invalid signature encoding")
		}
		remaining = bytes.TrimLeft(next, "\r\n \t")
		if !pins[id] || good[id] {
			continue
		}
		var digest []byte
		switch algorithm {
		case "sha1":
			digest = d1[:]
		case "sha256":
			digest = d256[:]
		default:
			continue
		}
		for _, cert := range certs {
			if cert.identity != id || cert.signingDigest != keyID || c.ValidAfter.Before(cert.published) || !c.ValidAfter.Before(cert.expires) {
				continue
			}
			// dir-spec 1.3 signs the digest without an ASN.1 algorithm identifier.
			if rsa.VerifyPKCS1v15(cert.signingKey, 0, digest, block.Bytes) == nil {
				good[id] = true
				break
			}
		}
	}
	if len(good) <= len(pins)/2 {
		return nil, fmt.Errorf("consensus: authority quorum not met: %d valid, need %d", len(good), len(pins)/2+1)
	}
	c.AuthorityCertificates = bytes.Clone(certificates)
	c.authenticated = true
	return c, nil
}

func parseAuthorityCertificates(data []byte, now time.Time) ([]authorityCertificate, error) {
	if len(data) == 0 || len(data) > 4<<20 {
		return nil, fmt.Errorf("directory: invalid authority certificate response size")
	}
	var certs []authorityCertificate
	count := 0
	for data = bytes.TrimLeft(data, "\r\n \t"); len(data) != 0; data = bytes.TrimLeft(data, "\r\n \t") {
		if !bytes.HasPrefix(data, []byte("dir-key-certificate-version ")) || count >= 64 {
			return nil, fmt.Errorf("directory: malformed or excessive authority certificates")
		}
		end := bytes.Index(data, []byte("\ndir-key-certification\n"))
		if end < 0 || end > 128<<10 {
			return nil, fmt.Errorf("directory: missing certificate signature")
		}
		signedEnd := end + len("\ndir-key-certification\n")
		block, rest, err := directoryPEM(data[signedEnd:], "SIGNATURE")
		if err != nil {
			return nil, err
		}
		cert, err := parseAuthorityCertificate(data[:signedEnd], block.Bytes, now)
		if err == nil {
			certs = append(certs, cert)
		}
		// Expired, unrecognized or incorrectly signed certificates do not count;
		// another valid certificate for the same identity may follow.
		count++
		data = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("directory: no valid authority certificates")
	}
	return certs, nil
}

func parseAuthorityCertificate(signed, signature []byte, now time.Time) (authorityCertificate, error) {
	var cert authorityCertificate
	var identityKey *rsa.PublicKey
	var cross []byte
	seen := make(map[string]bool)
	rest := signed
	for len(rest) != 0 {
		line, remaining, ok := bytes.Cut(rest, []byte{'\n'})
		if !ok {
			return cert, fmt.Errorf("directory: truncated certificate line")
		}
		rest = remaining
		f := strings.Fields(string(line))
		if len(f) == 0 {
			continue
		}
		key := f[0]
		if seen[key] {
			return cert, fmt.Errorf("directory: duplicate certificate field %s", key)
		}
		seen[key] = true
		switch key {
		case "dir-key-certificate-version":
			if len(f) != 2 || f[1] != "3" {
				return cert, fmt.Errorf("directory: unsupported authority certificate version")
			}
		case "fingerprint":
			if len(f) != 2 {
				return cert, fmt.Errorf("directory: invalid authority fingerprint")
			}
			var err error
			cert.identity, err = directoryDigest(f[1])
			if err != nil {
				return cert, err
			}
		case "dir-key-published", "dir-key-expires":
			if len(f) < 3 {
				return cert, fmt.Errorf("directory: missing certificate date")
			}
			t, err := time.Parse(CONSENSUS_DATE_FORMAT, f[1]+" "+f[2])
			if err != nil {
				return cert, err
			}
			if key == "dir-key-published" {
				cert.published = t
			} else {
				cert.expires = t
			}
		case "dir-identity-key", "dir-signing-key", "dir-key-crosscert":
			if len(f) != 1 {
				return cert, fmt.Errorf("directory: extra certificate key arguments")
			}
			kind := "RSA PUBLIC KEY"
			if key == "dir-key-crosscert" {
				kind = "ID SIGNATURE"
				if bytes.HasPrefix(rest, []byte("-----BEGIN SIGNATURE-----\n")) {
					kind = "SIGNATURE"
				}
			}
			block, next, err := directoryPEM(rest, kind)
			if err != nil {
				return cert, err
			}
			rest = next
			if key == "dir-key-crosscert" {
				cross = block.Bytes
				continue
			}
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil || pub.N.BitLen() < 1024 || pub.N.BitLen() > 8192 || pub.E < 3 || pub.E%2 == 0 {
				return cert, fmt.Errorf("directory: invalid authority RSA key")
			}
			if key == "dir-identity-key" {
				identityKey = pub
			} else {
				cert.signingKey = pub
				cert.signingDigest = sha1.Sum(x509.MarshalPKCS1PublicKey(pub))
			}
		case "dir-key-certification":
			if len(f) != 1 || len(rest) != 0 {
				return cert, fmt.Errorf("directory: misplaced certificate signature")
			}
		}
	}
	if identityKey == nil || cert.signingKey == nil || len(cross) == 0 || !seen["dir-key-published"] || !seen["dir-key-expires"] || now.Before(cert.published) || !now.Before(cert.expires) || !cert.expires.After(cert.published) {
		return cert, fmt.Errorf("directory: incomplete, future or expired authority certificate")
	}
	if cert.identity != sha1.Sum(x509.MarshalPKCS1PublicKey(identityKey)) {
		return cert, fmt.Errorf("directory: authority identity digest mismatch")
	}
	digest := sha1.Sum(signed)
	if rsa.VerifyPKCS1v15(identityKey, 0, digest[:], signature) != nil || rsa.VerifyPKCS1v15(cert.signingKey, 0, cert.identity[:], cross) != nil {
		return cert, fmt.Errorf("directory: invalid certificate signature or cross-signature")
	}
	return cert, nil
}

func directoryDigest(s string) ([20]byte, error) {
	var out [20]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		return out, fmt.Errorf("directory: invalid SHA-1 identity digest")
	}
	copy(out[:], b)
	return out, nil
}

func directoryPEM(data []byte, kind string) (*pem.Block, []byte, error) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----\n")) {
		return nil, nil, fmt.Errorf("directory: expected %s object", kind)
	}
	endMarker := []byte("-----END " + kind + "-----\n")
	end := bytes.Index(data, endMarker)
	if end < 0 || end+len(endMarker) > 16<<10 {
		return nil, nil, fmt.Errorf("directory: truncated or excessive PEM object")
	}
	end += len(endMarker)
	block, rest := pem.Decode(data[:end])
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, nil, fmt.Errorf("directory: malformed PEM object")
	}
	return block, data[end:], nil
}
