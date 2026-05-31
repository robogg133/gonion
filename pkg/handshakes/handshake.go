package handshakes

import "io"

type Handshake interface {
	Decode(io.Reader) error
	Encode(io.Writer) error
}

func Server_HandshakeType(htype uint8) Handshake {
	switch htype {
	case HTYPE_NTOR:
		return &Server_NTorHandshake{}
	case HTYPE_NTOR3:
		return &Server_NTor3Handshake{}
	default:
		return nil
	}
}
