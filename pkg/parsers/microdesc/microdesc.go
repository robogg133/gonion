// Package microdesc parses and formats Tor microdescriptor documents.
package microdesc

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/robogg133/gonion/pkg/common"
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
	return parseMicrodescFile(bufio.NewScanner(r), digests)
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
				out[i] = m
			}
		}
		builder.Reset()
		return nil
	}

	for scanner.Scan() {
		text := scanner.Text() + "\n"

		if text == "\n" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}

		if strings.HasPrefix(text, onionKeyPrefix) {
			if err := flush(); err != nil {
				return nil, err
			}
		}

		builder.WriteString(text)
	}

	if err := flush(); err != nil {
		return nil, err
	}

	return out, nil
}

func parseMicrodescBlock(data []byte) (*common.Microdesc, error) {

	m := &common.Microdesc{}

	r := bufio.NewReader(bytes.NewReader(data))

	for {
		txt, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
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

			m.NTorOnionKey, err = base64.RawStdEncoding.DecodeString(txt)
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

			m.IdEd25519, err = base64.RawStdEncoding.DecodeString(txt)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, "p "):
			txt = strings.TrimPrefix(txt, "p ")
			txt = strings.TrimSuffix(txt, "\n")

			ports := &common.Ports{}
			if err := common.ParsePortsLine(ports, txt); err != nil {
				return nil, err
			}

			m.ExitRules = ports
		}
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

	p, _ := pem.Decode(b.Bytes())

	return p.Bytes, nil
}

func parseFamilys(s string) (ids []*common.FamilyIDs, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {

		id := strings.SplitN(str, ":", 2)

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

		b, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}
		f.Digest = b

		family = append(family, f)
	}

	return family, nil
}