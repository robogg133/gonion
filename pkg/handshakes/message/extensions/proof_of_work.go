package extensions

import (
	"bytes"
)

const (
	PROOF_OF_WORK byte = 2
	POW
)

const powTotalSize = 1 + 16 + 4 + 4 + 16

type ProofOfWork struct {
	Scheme uint8

	Nonce    [16]byte
	Effort   [4]byte
	Seed     [4]byte
	Solution [16]byte
}

func (pow *ProofOfWork) Marshal() []byte {
	var buffer bytes.Buffer
	buffer.Grow(powTotalSize)

	buffer.WriteByte(pow.Scheme)

	buffer.Write(pow.Nonce[:])
	buffer.Write(pow.Effort[:])
	buffer.Write(pow.Seed[:])
	buffer.Write(pow.Solution[:])

	return buffer.Bytes()
}

func (pow *ProofOfWork) Unmarshal(r *bytes.Reader) error {
	scheme, err := r.ReadByte()
	if err != nil {
		return err
	}

	pow.Scheme = scheme

	buff := make([]byte, 16)

	//
	if _, err := r.Read(buff); err != nil {
		return err
	}
	pow.Nonce = [16]byte(buff)

	//
	if _, err := r.Read(buff[0:4]); err != nil {
		return err
	}
	pow.Effort = [4]byte(buff[0:4])

	//
	if _, err := r.Read(buff[0:4]); err != nil {
		return err
	}
	pow.Seed = [4]byte(buff[0:4])

	//
	if _, err := r.Read(buff); err != nil {
		return err
	}
	pow.Solution = [16]byte(buff)
	return nil
}
