// Package microdesc parses and formats Tor microdescriptor documents.
package microdesc

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers"
)

const (
	onionKeyPrefix     = "onion-key\n"
	ntorOnionKeyPrefix = "ntor-onion-key "
	familyPrefix       = "family "
	familyIDsPrefix    = "family-ids "
	idEd25519Prefix    = "id ed25519 "
)

// Parser implements common.MicrodescParser for microdescriptor documents.
type Parser struct{}

func (Parser) Parse(r io.Reader, digests []string) ([]*common.Microdesc, error) {
	data, err := parsers.ReadAll(r, 4<<20)
	if err != nil {
		return nil, err
	}
	if len(digests) > 92 {
		return nil, fmt.Errorf("microdescriptor: too many requested digests")
	}
	for _, digest := range digests {
		b, err := base64.RawStdEncoding.Strict().DecodeString(digest)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("microdescriptor: invalid requested digest")
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Hash the exact received bytes, never scanner-normalized CRLF or a
	// synthesized final newline (dir-spec 3.3).
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i+1], nil
		}
		if atEOF && len(data) != 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, nil
	})
	return parseMicrodescFile(scanner, digests)
}

func (Parser) Format(ms []*common.Microdesc) ([]byte, error) {
	var b bytes.Buffer

	for _, m := range ms {
		if m == nil {
			continue
		}

		if m.OnionKey != nil {
			b.WriteString(onionKeyPrefix)
			if err := pem.Encode(&b, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: m.OnionKey}); err != nil {
				return nil, err
			}
		}

		if m.NTorOnionKey != nil {
			fmt.Fprintf(&b, "%s%s\n", ntorOnionKeyPrefix, base64.RawStdEncoding.EncodeToString(m.NTorOnionKey))
		}

		if len(m.Family) > 0 {
			b.WriteString(familyPrefix)
			for i, f := range m.Family {
				if i > 0 {
					b.WriteByte(' ')
				}
				if f.Digest != nil {
					b.WriteString("$" + hex.EncodeToString(f.Digest))
				} else {
					b.WriteString(f.Nickname)
				}
			}
			b.WriteByte('\n')
		}

		if len(m.Familys) > 0 {
			b.WriteString(familyIDsPrefix)
			for i, f := range m.Familys {
				if i > 0 {
					b.WriteByte(' ')
				}
				fmt.Fprintf(&b, "%s:%s", f.Kind, base64.RawStdEncoding.EncodeToString(f.Value))
			}
			b.WriteByte('\n')
		}

		if len(m.IdEd25519) > 0 {
			fmt.Fprintf(&b, "%s%s\n", idEd25519Prefix, base64.RawStdEncoding.EncodeToString(m.IdEd25519))
		}

		if m.ExitRules != nil {
			fmt.Fprintf(&b, "p %s\n", common.FormatPortsPolicy(m.ExitRules))
		}

		b.WriteByte('\n')
	}

	return b.Bytes(), nil
}

// parseMicrodescFile filters microdescriptor blocks whose sha256 digest
// (over the whole block from its "onion-key" line through its last line,
// base64-raw encoded) matches one of the requested digests.
func parseMicrodescFile(scanner *bufio.Scanner, digests []string) ([]*common.Microdesc, error) {
	out := make([]*common.Microdesc, len(digests))

	var builder bytes.Buffer
	flush := func() error {
		if builder.Len() == 0 {
			return nil
		}
		block := builder.Bytes()
		digNow := sha256.Sum256(block)
		b64 := base64.RawStdEncoding.EncodeToString(digNow[:])

		for i, v := range digests {
			if b64 == v {
				m, err := parseMicrodescBlock(block)
				if err != nil {
					return err
				}
				m.RawDocument = bytes.Clone(block)
				out[i] = m
			}
		}
		builder.Reset()
		return nil
	}

	for scanner.Scan() {
		text := scanner.Text()

		if text == "\n" && builder.Len() == 0 {
			continue
		}

		if strings.HasPrefix(text, onionKeyPrefix) {
			if err := flush(); err != nil {
				return nil, err
			}
		}

		if builder.Len() == 0 && !strings.HasPrefix(text, onionKeyPrefix) {
			return nil, fmt.Errorf("microdescriptor: missing initial onion-key")
		}
		if builder.Len()+len(text) > 64<<10 {
			return nil, fmt.Errorf("microdescriptor: block too large")
		}
		builder.WriteString(text)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("microdescriptor: read: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}

	return out, nil
}

func parseMicrodescBlock(data []byte) (*common.Microdesc, error) {

	m := &common.Microdesc{}
	seen := make(map[string]bool)

	r := bufio.NewReader(bytes.NewReader(data))

	for {
		txt, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		fields := strings.Fields(txt)
		if len(fields) == 0 {
			continue
		}
		keyword := fields[0]
		if keyword == "id" && len(fields) > 1 {
			keyword += " " + fields[1]
		}
		switch keyword {
		case "onion-key", "ntor-onion-key", "family", "family-ids", "id ed25519", "p":
			if seen[keyword] {
				return nil, fmt.Errorf("microdescriptor: duplicate %s", keyword)
			}
			seen[keyword] = true
		}
		switch {
		case txt == onionKeyPrefix:
			m.OnionKey, err = parseOnionKey(r)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, ntorOnionKeyPrefix):
			txt = strings.TrimPrefix(txt, ntorOnionKeyPrefix)
			txt = strings.TrimSuffix(txt, "\n")

			m.NTorOnionKey, err = base64.RawStdEncoding.Strict().DecodeString(strings.TrimRight(txt, "="))
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, familyPrefix):
			txt = strings.TrimPrefix(txt, familyPrefix)
			txt = strings.TrimSuffix(txt, "\n")

			m.Family, err = parseFamily(txt)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(txt, familyIDsPrefix):
			txt = strings.TrimPrefix(txt, familyIDsPrefix)
			txt = strings.TrimSuffix(txt, "\n")

			m.Familys, err = parseFamilys(txt)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, idEd25519Prefix):
			txt = strings.TrimPrefix(txt, idEd25519Prefix)
			txt = strings.TrimSuffix(txt, "\n")

			m.IdEd25519, err = base64.RawStdEncoding.Strict().DecodeString(txt)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, "p "):
			txt = strings.TrimPrefix(txt, "p ")
			txt = strings.TrimSuffix(txt, "\n")

			ports := &common.Ports{}
			if err := parsers.ParsePorts(ports, txt); err != nil {
				return nil, err
			}

			m.ExitRules = ports
		}
	}

	if len(m.OnionKey) == 0 || len(m.NTorOnionKey) != 32 {
		return nil, fmt.Errorf("microdescriptor: missing onion key or invalid ntor key length")
	}
	if len(m.IdEd25519) != 0 && len(m.IdEd25519) != 32 {
		return nil, fmt.Errorf("microdescriptor: invalid Ed25519 key length")
	}
	if m.ExitRules == nil {
		m.ExitRules = &common.Ports{}
	}
	return m, nil
}

func parseOnionKey(r *bufio.Reader) ([]byte, error) {

	b := &bytes.Buffer{}

	for {
		txt, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		b.WriteString(txt)

		if strings.HasPrefix(txt, "-----END") {
			break
		}
	}

	p, rest := pem.Decode(b.Bytes())
	if p == nil || p.Type != "RSA PUBLIC KEY" || len(rest) != 0 {
		return nil, fmt.Errorf("microdescriptor: invalid onion-key PEM")
	}
	key, err := x509.ParsePKCS1PublicKey(p.Bytes)
	if err != nil || key.N.BitLen() != 1024 || key.E != 65537 {
		return nil, fmt.Errorf("microdescriptor: invalid RSA1024 onion key")
	}
	return p.Bytes, nil
}

func parseFamilys(s string) (ids []*common.FamilyIDs, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {

		id := strings.SplitN(str, ":", 2)
		if len(id) != 2 || id[0] == "" || id[1] == "" {
			return nil, fmt.Errorf("microdescriptor: invalid family-id")
		}

		a := &common.FamilyIDs{
			Kind: id[0],
		}
		a.Value, err = base64.RawStdEncoding.DecodeString(id[1])
		if err != nil {
			return nil, err
		}

		ids = append(ids, a)
	}

	return ids, nil
}

func parseFamily(s string) (family []common.Family, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {
		var f common.Family

		str, ok := strings.CutPrefix(str, "$")
		if !ok {
			f.Nickname = str
			family = append(family, f)
			continue
		}

		if i := strings.IndexAny(str, "=~"); i >= 0 {
			str = str[:i]
		}
		b, err := hex.DecodeString(str)
		if err != nil || len(b) != 20 {
			return nil, fmt.Errorf("microdescriptor: invalid family fingerprint")
		}
		f.Digest = b

		family = append(family, f)
	}

	return family, nil
}
