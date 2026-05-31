package handshakes

import (
	"crypto/ed25519"
	"io"
)

const HTYPE_NTOR byte = 0x0002

type Client_NTorHandshake struct {
	NodeID [20]byte

	KeyID     ed25519.PublicKey
	PublicKey ed25519.PublicKey
}

type Server_NTorHandshake struct {
	PublicKey ed25519.PublicKey
	Auth      []byte
}

func (ntor *Client_NTorHandshake) Encode(w io.Writer) error {
	if _, err := w.Write(ntor.NodeID[:]); err != nil {
		return err
	}
	if _, err := w.Write(ntor.KeyID); err != nil {
		return err
	}
	_, err := w.Write(ntor.PublicKey)
	return err
}

func (ntor *Server_NTorHandshake) Encode(w io.Writer) error { return nil }

func (ntor *Server_NTorHandshake) Decode(r io.Reader) error {
	pk := make([]byte, 32)
	auth := make([]byte, 32)

	if _, err := r.Read(pk); err != nil {
		return err
	}
	if _, err := r.Read(auth); err != nil {
		return err
	}

	ntor.PublicKey = pk
	ntor.Auth = auth
	return nil
}
