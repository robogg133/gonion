package handshakes

import (
	"crypto/ecdh"
	"fmt"
	"io"
)

const HTYPE_NTOR uint16 = 0x0002

type Client_NTorHandshake struct {
	NodeID [20]byte

	KeyID      *ecdh.PublicKey  // ntor-onion-key
	PublicKey  *ecdh.PublicKey  // curve25519
	PrivateKey *ecdh.PrivateKey // curve25519
}

type Server_NTorHandshake struct {
	PrivateKey *ecdh.PrivateKey // curve25519
	PublicKey  *ecdh.PublicKey  // curve25519
	Auth       []byte
}

func (ntor *Client_NTorHandshake) Encode(w io.Writer) error {
	if _, err := w.Write(ntor.NodeID[:]); err != nil {
		return err
	}
	if _, err := w.Write(ntor.KeyID.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(ntor.PublicKey.Bytes())
	return err
}
func (ntor *Client_NTorHandshake) Decode(r io.Reader) error {
	buff := make([]byte, 32)
	pk := make([]byte, 32)

	if _, err := io.ReadFull(r, buff[0:20]); err != nil {
		return err
	}
	ntor.NodeID = [20]byte(buff)

	if _, err := io.ReadFull(r, buff); err != nil {
		return err
	}
	var err error
	ntor.KeyID, err = ecdh.X25519().NewPublicKey(buff)
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(r, pk); err != nil {
		return err
	}

	ntor.PublicKey, err = ecdh.X25519().NewPublicKey(pk)
	return err
}

func (ntor *Server_NTorHandshake) Encode(w io.Writer) error {
	if len(ntor.Auth) != 32 {
		return fmt.Errorf("encode server ntor handshake: invalid auth field length %d", len(ntor.Auth))
	}

	if _, err := w.Write(ntor.PublicKey.Bytes()); err != nil {
		return err
	}

	if _, err := w.Write(ntor.Auth); err != nil {
		return err
	}

	return nil
}

func (ntor *Server_NTorHandshake) Decode(r io.Reader) error {
	pk := make([]byte, 32)
	ntor.Auth = make([]byte, 32)

	if _, err := io.ReadFull(r, pk); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, ntor.Auth); err != nil {
		return err
	}

	var err error
	ntor.PublicKey, err = ecdh.X25519().NewPublicKey(pk)
	return err
}
