package onion

import (
	"bytes"
	"crypto/sha3"
	"encoding/base32"
	"fmt"
	"strings"
)

const ChecksumString = ".onion checksum"

const HostnameSufix = ".onion"

type OnionHostname struct {
	Pk       [32]byte
	checksum []byte
	Version  uint8
}

func NewFromString(addr string) (*OnionHostname, error) {
	addr = strings.TrimSuffix(addr, HostnameSufix)
	if len(addr) != 56 {
		return nil, fmt.Errorf("onion: invalid onion hostname length")
	}
	addr = strings.ToUpper(addr)

	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(addr)
	if err != nil {
		return nil, err
	}

	o := new(OnionHostname)

	o.Pk = [32]byte(b[0:32])
	o.Version = b[34]

	if err := o.runChecksum(); err != nil {
		return nil, err
	}

	if !bytes.Equal(o.checksum[0:2], b[32:34]) {
		return nil, fmt.Errorf("onion: invalid checksum for onion hostname")
	}
	return o, nil
}

func (addr *OnionHostname) runChecksum() error {
	if addr.checksum != nil {
		return nil
	}

	h := sha3.New256()
	h.Write([]byte(ChecksumString))
	h.Write(addr.Pk[:])
	h.Write([]byte{addr.Version})

	addr.checksum = h.Sum(nil)
	return nil
}

func (addr *OnionHostname) String() string {
	addr.runChecksum()

	a := make([]byte, 35)
	a = append(addr.Pk[:], append(addr.checksum[0:2], addr.Version)...)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(a)) + HostnameSufix
}
