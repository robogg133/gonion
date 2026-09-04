package onion

import (
	"bytes"
	"crypto/sha3"
	"encoding/base32"
	"fmt"
	"net"
	"strings"

	"filippo.io/edwards25519"
)

const ChecksumString = ".onion checksum"

const HostnameSufix = ".onion"

type OnionHostname struct {
	Pk       [32]byte
	checksum []byte
	Version  uint8
}

func NewFromString(addr string) (*OnionHostname, error) {
	host, err := Host(addr)
	if err != nil {
		return nil, err
	}
	addr = strings.TrimSuffix(strings.ToLower(host), HostnameSufix)
	if len(addr) != 56 {
		return nil, fmt.Errorf("onion: invalid onion hostname length")
	}
	addr = strings.ToUpper(addr)

	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("onion: decode hostname: %w", err)
	}

	o := new(OnionHostname)

	o.Pk = [32]byte(b[0:32])
	o.Version = b[34]
	if o.Version != 3 {
		return nil, fmt.Errorf("onion: unsupported version %d", o.Version)
	}
	if !validPublicKey(o.Pk[:]) {
		return nil, fmt.Errorf("onion: public key has a torsion component")
	}

	if err := o.runChecksum(); err != nil {
		return nil, err
	}

	if !bytes.Equal(o.checksum[0:2], b[32:34]) {
		return nil, fmt.Errorf("onion: invalid checksum for onion hostname")
	}
	return o, nil
}

// Host extracts the hostname accepted by the dial APIs. Bare onion hostnames
// remain accepted for existing direct Circuit.Dial callers.
func Host(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("onion: invalid address %q: %w", addr, err)
	}
	return host, nil
}

func IsOnion(addr string) (bool, error) {
	host, err := Host(addr)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(strings.ToLower(host), HostnameSufix), nil
}

func validPublicKey(encoded []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(encoded)
	if err != nil || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	// Little-endian order l of the prime-order Ed25519 subgroup. [l]P is the
	// identity exactly when P has no torsion component.
	order := [...]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	result := edwards25519.NewIdentityPoint()
	addend := new(edwards25519.Point).Set(p)
	for _, octet := range order {
		for bit := 0; bit < 8; bit++ {
			if octet&(1<<bit) != 0 {
				result.Add(result, addend)
			}
			addend.Add(addend, addend)
		}
	}
	return result.Equal(edwards25519.NewIdentityPoint()) == 1
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

	a := make([]byte, 0, 35)
	a = append(addr.Pk[:], append(addr.checksum[0:2], addr.Version)...)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(a)) + HostnameSufix
}
