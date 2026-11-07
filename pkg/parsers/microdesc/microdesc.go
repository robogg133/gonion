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
	"github.com/robogg133/gonion/pkg/parsers"
)

const (
	onionKeyPrefix     = "onion-key\n"
	ntorOnionKeyPrefix = "ntor-onion-key "
	familyPrefix       = "family "
	familyIDsPrefix    = "family-ids "
	idEd25519Prefix    = "id ed25519 "
)

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
	// Hash exact received bytes, never normalized line endings or synthesized newlines.
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

// parseMicrodescFile splits received bytes into bounded digest-addressed blocks.
func parseMicrodescFile(scanner *bufio.Scanner, digests []string) ([]*common.Microdesc, error) {
	out := make([]*common.Microdesc, len(digests))
	var builder bytes.Buffer
	flush := func() error {
		if builder.Len() == 0 {
			return nil
		}
		block := builder.Bytes()
		sum := sha256.Sum256(block)
		digest := base64.RawStdEncoding.EncodeToString(sum[:])
		for i, wanted := range digests {
			if digest != wanted {
				continue
			}
			m, err := common.ParseMicrodescriptor(block, wanted)
			if err != nil {
				return err
			}
			out[i] = m
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
