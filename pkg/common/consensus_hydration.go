package common

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// ParseMicrodescriptor verifies the SHA-256 digest of the complete wire block
// and parses the fields used by hydrated consensus relay selection. Batch
// directory parsing and trust hydration share this exact parser.
func ParseMicrodescriptor(raw []byte, digest string) (*Microdesc, error) {
	sum := sha256.Sum256(raw)
	if len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' || base64.RawStdEncoding.EncodeToString(sum[:]) != digest || !bytes.HasPrefix(raw, []byte("onion-key\n")) {
		return nil, fmt.Errorf("microdescriptor: invalid digest or framing")
	}
	m := &Microdesc{RawDocument: bytes.Clone(raw), ExitRules: &Ports{}}
	seen := make(map[string]bool)
	for len(raw) != 0 {
		line, rest, ok := bytes.Cut(raw, []byte{'\n'})
		if !ok {
			return nil, fmt.Errorf("microdescriptor: incomplete line")
		}
		raw = rest
		text := string(line)
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		key := fields[0]
		if key == "id" && len(fields) > 1 {
			key += " " + fields[1]
		}
		switch key {
		case "onion-key", "ntor-onion-key", "family", "family-ids", "id ed25519", "p":
			if seen[key] {
				return nil, fmt.Errorf("microdescriptor: duplicate %s", key)
			}
			seen[key] = true
		}
		switch key {
		case "onion-key":
			if text != "onion-key" || !bytes.HasPrefix(raw, []byte("-----BEGIN RSA PUBLIC KEY-----\n")) {
				return nil, fmt.Errorf("microdescriptor: invalid onion-key PEM")
			}
			end := bytes.Index(raw, []byte("-----END RSA PUBLIC KEY-----\n"))
			if end < 0 || end > 16<<10 {
				return nil, fmt.Errorf("microdescriptor: invalid onion-key PEM")
			}
			end += len("-----END RSA PUBLIC KEY-----\n")
			block, trailing := pem.Decode(raw[:end])
			if block == nil || block.Type != "RSA PUBLIC KEY" || len(block.Headers) != 0 || len(trailing) != 0 {
				return nil, fmt.Errorf("microdescriptor: invalid onion-key PEM")
			}
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil || pub.N.BitLen() != 1024 || pub.E != 65537 {
				return nil, fmt.Errorf("microdescriptor: invalid RSA1024 onion key")
			}
			m.OnionKey = bytes.Clone(block.Bytes)
			raw = raw[end:]
		case "ntor-onion-key":
			if !strings.HasPrefix(text, "ntor-onion-key ") {
				return nil, fmt.Errorf("microdescriptor: invalid ntor key")
			}
			var err error
			m.NTorOnionKey, err = base64.RawStdEncoding.Strict().DecodeString(strings.TrimRight(strings.TrimPrefix(text, "ntor-onion-key "), "="))
			if err != nil || len(m.NTorOnionKey) != 32 {
				return nil, fmt.Errorf("microdescriptor: invalid ntor key")
			}
		case "id ed25519":
			if !strings.HasPrefix(text, "id ed25519 ") {
				return nil, fmt.Errorf("microdescriptor: invalid Ed25519 identity")
			}
			var err error
			m.IdEd25519, err = base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(text, "id ed25519 "))
			if err != nil || len(m.IdEd25519) != 32 {
				return nil, fmt.Errorf("microdescriptor: invalid Ed25519 identity")
			}
		case "family":
			if !strings.HasPrefix(text, "family ") {
				return nil, fmt.Errorf("microdescriptor: invalid family")
			}
			var err error
			m.Family, err = ParseRelayFamily(strings.TrimPrefix(text, "family "))
			if err != nil {
				return nil, err
			}
		case "family-ids":
			if !strings.HasPrefix(text, "family-ids ") {
				return nil, fmt.Errorf("microdescriptor: invalid family IDs")
			}
			for _, item := range strings.Fields(strings.TrimPrefix(text, "family-ids ")) {
				kind, encoded, ok := strings.Cut(item, ":")
				value, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
				if !ok || kind == "" || err != nil {
					return nil, fmt.Errorf("microdescriptor: invalid family ID")
				}
				m.Familys = append(m.Familys, &FamilyIDs{Kind: kind, Value: value})
			}
		case "p":
			if !strings.HasPrefix(text, "p ") {
				return nil, fmt.Errorf("microdescriptor: invalid exit policy")
			}
			if err := ParseDirectoryPorts(m.ExitRules, strings.TrimPrefix(text, "p ")); err != nil {
				return nil, err
			}
		}
	}
	if !seen["onion-key"] || !seen["ntor-onion-key"] {
		return nil, fmt.Errorf("microdescriptor: missing onion or ntor key")
	}
	return m, nil
}
