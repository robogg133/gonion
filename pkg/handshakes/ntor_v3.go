package handshakes

import (
	"crypto/ed25519"
	"io"

	"github.com/robogg133/gonion/pkg/handshakes/message"
)

const HTYPE_NTOR3 byte = 0x0003

type Client_NTor3Handshake struct {
	NodeID ed25519.PublicKey

	KeyID     []byte
	PublicKey ed25519.PublicKey
	Message   *message.Messages
	MAC       []byte

	TranslationTable message.TranslationTable
}

type Server_NTor3Handshake struct {
	PublicKey ed25519.PublicKey
	Auth      []byte
	Messages  *message.Messages

	TranslationTable message.TranslationTable
}

func (ntor *Client_NTor3Handshake) Encode(w io.Writer) error {
	w.Write(ntor.NodeID)

	w.Write(ntor.KeyID)
	w.Write(ntor.PublicKey)
	w.Write(ntor.Message.Marshal())
	w.Write(ntor.MAC)
	return nil
}

func (ntor *Server_NTor3Handshake) Encode(io.Writer) error { return nil }
func (ntor *Server_NTor3Handshake) Decode(r io.Reader) error {
	pk := make([]byte, 32)
	_, err := r.Read(pk)
	if err != nil {
		return err
	}
	ntor.PublicKey = pk

	auth := make([]byte, 32)
	if _, err := r.Read(auth); err != nil {
		return err
	}
	ntor.Auth = auth

	ntor.Messages, err = message.Unmarshal(r, ntor.TranslationTable)
	return err
}
