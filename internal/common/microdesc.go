package common

// This file have some perfomance issues and NEED's a refactor in the future

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"io"
	"strings"
)

const (
	onion_key_microdesc_prefix      = "onion-key\n"
	ntor_onion_key_microdesc_prefix = "ntor-onion-key "
	family_microdesc_prefix         = "family "
	family_ids_microdesc_prefix     = "family-ids "
	id_ed25519_microdesc_prefix     = "id ed25519 "
)

type Microdesc struct {
	OnionKey     []byte
	NTorOnionKey []byte
	IdEd25519    []byte
	Family       [][]byte
	Familys      []*FamilyIDs

	ExitRules *Ports
}

type FamilyIDs struct {
	Kind  string
	Value []byte
}

func ParseMicrodescFile(reader *bufio.Reader, digests [][]byte) (microdesc []*Microdesc, err error) {
	builder := &bytes.Buffer{}

	microdesc = make([]*Microdesc, len(digests))

	for {
		text, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		builder.Write(text)

		if strings.HasPrefix(string(text), id_ed25519_microdesc_prefix) {

			digNow := sha256.Sum256(builder.Bytes())

			found := false
			index := 0

			// idk, this isn't used too many times so i think it can be that for now and later be changed for a map
			for i, v := range digests {
				if bytes.Equal(digNow[:], v) {
					found = true
					index = i
				}
			}

			if !found {
				return nil, errors.New("invalid dir")
			}

			m, err := parseMicrodescBlock(builder.Bytes())
			if err != nil {
				return nil, err
			}
			microdesc[index] = m
			builder.Reset()
		}

	}

	return microdesc, nil

}

func parseMicrodescBlock(data []byte) (*Microdesc, error) {

	m := &Microdesc{}

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
		case txt == onion_key_microdesc_prefix:
			m.OnionKey = parseOnionKey(r)

		case strings.HasPrefix(txt, ntor_onion_key_microdesc_prefix):
			txt = strings.TrimPrefix(txt, ntor_onion_key_microdesc_prefix)
			txt = strings.TrimSuffix(txt, "\n")

			var err error
			m.NTorOnionKey, err = base64.RawStdEncoding.DecodeString(txt)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, family_microdesc_prefix):
			txt = strings.TrimPrefix(txt, family_microdesc_prefix)
			txt = strings.TrimSuffix(txt, "\n")

			var err error
			m.Family, err = parseFamily(txt)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(txt, family_ids_microdesc_prefix):
			txt = strings.TrimPrefix(txt, family_ids_microdesc_prefix)
			txt = strings.TrimSuffix(txt, "\n")

			var err error
			m.Familys, err = parseFamilys(txt)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, id_ed25519_microdesc_prefix):
			txt = strings.TrimPrefix(txt, id_ed25519_microdesc_prefix)
			txt = strings.TrimSuffix(txt, "\n")

			var err error
			m.IdEd25519, err = base64.RawStdEncoding.DecodeString(txt)
			if err != nil {
				return nil, err
			}

		case strings.HasPrefix(txt, "p "):
			txt = strings.TrimPrefix(txt, "p ")
			txt = strings.TrimSuffix(txt, "\n")

			ports := &Ports{}
			if err := ParsePortsLine(ports, txt); err != nil {
				return nil, err
			}

			m.ExitRules = ports
		}
	}

	return m, nil
}

func parseOnionKey(r *bufio.Reader) []byte {

	b := &bytes.Buffer{}

	for {
		txt, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		b.WriteString(txt)

		if strings.HasPrefix(txt, "-----END") {
			break
		}
	}

	p, _ := pem.Decode(b.Bytes())

	return p.Bytes
}

func parseFamilys(s string) (ids []*FamilyIDs, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {

		id := strings.SplitN(str, ":", 2)

		a := &FamilyIDs{
			Kind: id[0],
		}
		var err error
		a.Value, err = base64.RawStdEncoding.DecodeString(id[1])
		if err != nil {
			return nil, err
		}

		ids = append(ids, a)
	}

	return nil, nil
}

func parseFamily(s string) (family [][]byte, err error) {
	split := strings.SplitSeq(s, " ")

	for str := range split {
		str = strings.TrimPrefix(str, "$")

		b, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}

		family = append(family, b)
	}

	return family, nil
}
