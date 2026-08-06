package relay

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
)

// Hidden-service relay commands (tor src/core/or/or.h: RELAY_COMMAND_*).
const (
	COMMAND_ESTABLISH_INTRO        uint8 = 32
	COMMAND_ESTABLISH_RENDEZVOUS   uint8 = 33
	COMMAND_INTRODUCE1             uint8 = 34
	COMMAND_INTRODUCE2             uint8 = 35
	COMMAND_RENDEZVOUS1            uint8 = 36
	COMMAND_RENDEZVOUS2            uint8 = 37
	COMMAND_INTRO_ESTABLISHED      uint8 = 38
	COMMAND_RENDEZVOUS_ESTABLISHED uint8 = 39
	COMMAND_INTRODUCE_ACK          uint8 = 40
)

// introAuthTypeED25519 is the only INTRODUCTION AUTH_KEY_TYPE for v3
// (introduction-protocol §EST_INTRO / §FMT_INTRO1).
const introAuthTypeED25519 = 2

const cookieLen = 20

// hsMacLen is the HANDSHAKE_AUTH/MAC size (32 bytes, SHA-3-256 truncated),
// introduction-protocol §EST_INTRO.
const hsMacLen = 32

// Ext is a variable-length protocol extension (EST_INTRO / FMT_INTRO1 /
// INTRODUCE_ACK). Wire: EXT_FIELD_TYPE (1) || EXT_FIELD_LEN (1) || EXT_FIELD.
type Ext struct {
	Type byte
	Data []byte
}

// introHead is the shared extensible prefix of INTRODUCE1/INTRODUCE2. Embedded
// so the AuthKey/LegacyKeyID/Exts fields are promoted onto the cells.
type introHead struct {
	LegacyKeyID [20]byte
	AuthKey     ed25519.PublicKey
	Exts        []Ext
}

func (h *introHead) encodeIntroHead(w io.Writer) error {
	if len(h.AuthKey) != ed25519.PublicKeySize {
		return fmt.Errorf("relay: intro auth key must be %d bytes, got %d", ed25519.PublicKeySize, len(h.AuthKey))
	}
	if _, err := w.Write(h.LegacyKeyID[:]); err != nil {
		return err
	}
	if err := writeByte(w, introAuthTypeED25519); err != nil {
		return err
	}
	if err := writeU16(w, len(h.AuthKey)); err != nil {
		return err
	}
	if _, err := w.Write(h.AuthKey); err != nil {
		return err
	}
	return encodeExts(w, h.Exts)
}

func (h *introHead) decodeIntroHead(r io.Reader) error {
	if _, err := io.ReadFull(r, h.LegacyKeyID[:]); err != nil {
		return err
	}
	authType, err := readLenByte(r)
	if err != nil {
		return err
	}
	if authType != introAuthTypeED25519 {
		return fmt.Errorf("relay: unsupported intro auth type %d", authType)
	}
	key, err := readLenP(r)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("relay: intro auth key must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
	}
	h.AuthKey = ed25519.PublicKey(key)
	h.Exts, err = decodeExts(r)
	return err
}

func encodeExts(w io.Writer, exts []Ext) error {
	if len(exts) > 255 {
		return fmt.Errorf("relay: too many extensions: %d", len(exts))
	}
	if err := writeByte(w, byte(len(exts))); err != nil {
		return err
	}
	for _, e := range exts {
		if len(e.Data) > 255 {
			return fmt.Errorf("relay: extension field too long: %d", len(e.Data))
		}
		if err := writeByte(w, e.Type); err != nil {
			return err
		}
		if err := writeByte(w, byte(len(e.Data))); err != nil {
			return err
		}
		if _, err := w.Write(e.Data); err != nil {
			return err
		}
	}
	return nil
}

func decodeExts(r io.Reader) ([]Ext, error) {
	n, err := readLenByte(r)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	exts := make([]Ext, 0, int(n))
	for range n {
		var e Ext
		if e.Type, err = readLenByte(r); err != nil {
			return nil, err
		}
		if l, err := readLenByte(r); err != nil {
			return nil, err
		} else if l > 0 {
			e.Data = make([]byte, int(l))
			if _, err := io.ReadFull(r, e.Data); err != nil {
				return nil, err
			}
		}
		exts = append(exts, e)
	}
	return exts, nil
}

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func writeU16(w io.Writer, v int) error {
	if v < 0 || v > 0xffff {
		return fmt.Errorf("relay: u16 field out of range: %d", v)
	}
	return binary.Write(w, binary.BigEndian, uint16(v))
}

func readLenByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func readLenP(r io.Reader) ([]byte, error) {
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(p[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func readExact(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ponytail: this file groups the HS command numbers, the shared Ext/primitive
// helpers and the INTRODUCE prefix. If more intro head variants appear, move
// introHead to its own file.
