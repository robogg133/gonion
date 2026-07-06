package handshakes

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/crypto"
)

const (
	PROTOID_NTOR  string = "ntor-curve25519-sha256-1"
	PROTOID_NTOR3 string = "ntor3-curve25519-sha3_256-1"
)

const (
	t_mac    string = ":mac"
	t_key    string = ":key_extract"
	t_verify string = ":verify"
	m_expand string = ":key_expand"
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

func Client_HandshakeType(htype uint16) Handshake {
	switch htype {
	case HTYPE_NTOR:
		return &Client_NTorHandshake{}
	case HTYPE_NTOR3:
		return &Client_NTor3Handshake{}
	default:
		return nil
	}
}

/*
ALL FUNCTIONS MUST IMPLEMENT EVERYTHING IN THAT WAY

X = Client PublicKey
Y = Server PublicKey
B = Server ntor-onion-key
ID= Server NodeID

secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
KEY_SEED = H(secret_input, t_key)
verify = H(secret_input, t_verify)
auth_input = verify | ID | B | Y | X | PROTOID | "Server"
*/

func (c *Client_NTorHandshake) secretInput(s *Server_NTorHandshake, NTorOnionKey *ecdh.PublicKey) ([]byte, error) {
	var secretInput bytes.Buffer

	expYx, err := c.PrivateKey.ECDH(s.PublicKey) // EXP(Y,x)
	if err != nil {
		return nil, err
	}
	secretInput.Write(expYx)

	expBx, err := c.PrivateKey.ECDH(NTorOnionKey) // EXP(B, x)
	if err != nil {
		return nil, err
	}
	secretInput.Write(expBx) // EXP(B,x)

	secretInput.Write(c.NodeID[:])          // ID
	secretInput.Write(NTorOnionKey.Bytes()) // B
	secretInput.Write(c.PublicKey.Bytes())  // X
	secretInput.Write(s.PublicKey.Bytes())  // Y
	secretInput.WriteString(PROTOID_NTOR)   // PROTOID

	return secretInput.Bytes(), nil
}

func (c *Client_NTorHandshake) Derive(s *Server_NTorHandshake, NTorOnionKey *ecdh.PublicKey) (*crypto.CircuitKeys, error) {

	// Calc KEY_SEED
	secretInput, err := c.secretInput(s, NTorOnionKey)
	if err != nil {
		return nil, err
	}
	keySeed := hNtor(secretInput, t_key)

	// Verify
	verify := hNtor(secretInput, t_verify)
	if err := authVerify(verify, NTorOnionKey.Bytes(), c.PublicKey.Bytes(), s.PublicKey.Bytes(), c.NodeID[:], s.Auth, PROTOID_NTOR); err != nil {
		return nil, err
	}

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

func authVerify(verify, ntorOnionKey, X, Y, ID, compareAuth []byte, protoid string) error {

	verifyHash := hmac.New(sha256.New, []byte(protoid+t_mac))
	verifyHash.Write(verify)
	verifyHash.Write(ID)               // ID
	verifyHash.Write(ntorOnionKey)     // B
	verifyHash.Write(Y)                // Y
	verifyHash.Write(X)                // X
	verifyHash.Write([]byte(protoid))  // PROTOID
	verifyHash.Write([]byte("Server")) // "Server"

	authInput := verifyHash.Sum(nil)
	if !bytes.Equal(authInput, compareAuth) {
		return fmt.Errorf("ntor_handshake: invalid auth field")
	}
	return nil
}

func hNtor(data []byte, tag string) []byte {
	h := hmac.New(sha256.New, []byte(PROTOID_NTOR+tag))
	h.Write(data)
	return h.Sum(nil)
}
