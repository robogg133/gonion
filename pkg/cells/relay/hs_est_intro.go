package relay

import (
	"crypto/ed25519"
	"fmt"
	"io"
)

// EstIntroCell establishes an introduction point on a relay. Wire (v3):
//
//	AUTH_KEY_TYPE(1) AUTH_KEY_LEN(2) AUTH_KEY | N_EXTENSIONS(1) exts
//	HANDSHAKE_AUTH(32) SIG_LEN(2) SIG
type EstIntroCell struct {
	StreamID uint16

	AuthKey ed25519.PublicKey // KP_hs_ipt_sid
	Exts    []Ext             // EST_INTRO extensions (e.g. DOS_PARAMS)
	MAC     []byte            // HANDSHAKE_AUTH, 32-byte MAC of prior fields w/ KH
	Sig     []byte            // ed25519 signature over prior fields
}

func (*EstIntroCell) ID() uint8              { return COMMAND_ESTABLISH_INTRO }
func (c *EstIntroCell) GetStreamID() uint16  { return c.StreamID }
func (c *EstIntroCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *EstIntroCell) Encode(w io.Writer) error {
	if len(c.AuthKey) != ed25519.PublicKeySize {
		return fmt.Errorf("relay: ESTABLISH_INTRO auth key must be %d bytes, got %d", ed25519.PublicKeySize, len(c.AuthKey))
	}
	if len(c.MAC) != hsMacLen {
		return fmt.Errorf("relay: ESTABLISH_INTRO MAC must be %d bytes, got %d", hsMacLen, len(c.MAC))
	}
	if err := writeByte(w, introAuthTypeED25519); err != nil {
		return err
	}
	if err := writeU16(w, len(c.AuthKey)); err != nil {
		return err
	}
	if _, err := w.Write(c.AuthKey); err != nil {
		return err
	}
	if err := encodeExts(w, c.Exts); err != nil {
		return err
	}
	if _, err := w.Write(c.MAC); err != nil {
		return err
	}
	if len(c.Sig) != ed25519.SignatureSize {
		return fmt.Errorf("relay: ESTABLISH_INTRO sig must be %d bytes, got %d", ed25519.SignatureSize, len(c.Sig))
	}
	if err := writeU16(w, len(c.Sig)); err != nil {
		return err
	}
	_, err := w.Write(c.Sig)
	return err
}

func (c *EstIntroCell) Decode(r io.Reader) error {
	authType, err := readLenByte(r)
	if err != nil {
		return err
	}
	if authType != introAuthTypeED25519 {
		return fmt.Errorf("relay: unsupported ESTABLISH_INTRO auth type %d", authType)
	}
	key, err := readLenP(r)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("relay: ESTABLISH_INTRO auth key must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
	}
	c.AuthKey = ed25519.PublicKey(key)
	if c.Exts, err = decodeExts(r); err != nil {
		return err
	}
	if c.MAC, err = readExact(r, hsMacLen); err != nil {
		return err
	}
	sig, err := readLenP(r)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("relay: ESTABLISH_INTRO sig must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	c.Sig = sig
	return nil
}
