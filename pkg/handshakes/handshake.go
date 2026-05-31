package handshakes

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"github.com/robogg133/gonion/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

const (
	PROTOID_NTOR  = "ntor-curve25519-sha256-1"
	PROTOID_NTOR3 = "ntor3-curve25519-sha3_256-1"
)

const (
	t_mac    = ":mac"
	t_key    = ":key_extract"
	t_verify = ":verify"
	m_expand = ":key_expand"
)

type values struct {
	KeySeed []byte
}

type Handshake interface {
	Decode(io.Reader) error
	Encode(io.Writer) error
}

func Server_HandshakeType(htype uint16) Handshake {
	switch htype {
	case HTYPE_NTOR:
		return &Server_NTorHandshake{}
	case HTYPE_NTOR3:
		return &Server_NTor3Handshake{}
	default:
		return nil
	}
}

/*
X = Client PublicKey
Y = Server PublicKey
B = Server ntor-onion-key
ID= Server NodeID

secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
KEY_SEED = H(secret_input, t_key)
verify = H(secret_input, t_verify)
auth_input = verify | ID | B | Y | X | PROTOID | "Server"
*/

func (c *Client_NTorHandshake) Derive(s *Server_NTorHandshake, NTorOnionKey []byte) (*crypto.CircuitKeys, error) {

	// Calc secret_input
	var secretInput bytes.Buffer

	expYx, err := curve25519.X25519(s.PublicKey, c.PublicKey)
	if err != nil {
		return nil, err
	}
	secretInput.Write(expYx) // EXP(Y,x)

	expBx, err := curve25519.X25519(NTorOnionKey, c.PublicKey)
	if err != nil {
		return nil, err
	}
	secretInput.Write(expBx) // EXP(B,x)

	secretInput.Write(c.NodeID[:])        // ID
	secretInput.Write(NTorOnionKey)       // B
	secretInput.Write(c.PublicKey)        // X
	secretInput.Write(s.PublicKey)        // Y
	secretInput.WriteString(PROTOID_NTOR) // PROTOID

	// Calc KEY_SEED

	hash := hmac.New(sha256.New, []byte(PROTOID_NTOR+t_key))

	keySeed := hash.Sum(secretInput.Bytes())

	keyStream, err := hkdf.Expand(sha256.New, keySeed, PROTOID_NTOR+m_expand, 92)
	if err != nil {
		return nil, err
	}

	keys := &crypto.CircuitKeys{
		Df: keyStream[0:20],
		Db: keyStream[20:40],
		Kf: keyStream[40:56],
		Kb: keyStream[56:72],
		KH: keyStream[72:92],
	}
	return keys, nil
}
