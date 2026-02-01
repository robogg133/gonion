package circuit

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"log"

	"github.com/robogg133/gonion/connection"
	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/shared"
	"github.com/robogg133/gonion/tor_crypto"
)

func ConnectToRelayAndGetConsensus(ipaddr string, orport uint16) (*shared.Consensus, error) {

	torConn, err := connection.OpenConnection(ipaddr, orport)
	if err != nil {
		log.Fatal(err)
	}

	torConn.CircuitID = cells.MSB(1)
	x, err := torConn.SendCreateFast()
	if err != nil {
		log.Fatal(err)
	}

	c, err := torConn.ReadCreatedFast()
	if err != nil {
		log.Fatal(err)
	}

	keys, err := tor_crypto.DeriveKeysCreateFast(x, c.Y)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(keys.KH, c.KH[:]) {
		return nil, fmt.Errorf("KH key don't match")
	}

	torConn.ForwardDigest = sha1.New()
	torConn.ForwardDigest.Write(keys.Df)

	torConn.BackWardsDigest = sha1.New()
	torConn.BackWardsDigest.Write(keys.Db)

	block, err := aes.NewCipher(keys.Kf)
	if err != nil {
		log.Fatal(err)
	}
	tmp := make([]byte, 16)
	torConn.KeyForwardAES128CTR = cipher.NewCTR(block, tmp)

	block2, err := aes.NewCipher(keys.Kb)
	if err != nil {
		log.Fatal(err)
	}
	tmp = make([]byte, 16)
	torConn.KeyBackwardsAES128CTR = cipher.NewCTR(block2, tmp)

	if err := torConn.SendRelayBeginDir(); err != nil {
		return nil, err
	}

	if err := torConn.ReadRelayCell(); err != nil {
		return nil, err
	}
	if err := torConn.SendRelayGetConsensus(); err != nil {
		return nil, err
	}

	data, err := torConn.ReadRelayData()
	if err != nil {
		return nil, err
	}

	con, err := shared.ParseConsensus(bufio.NewScanner(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}

	cellDestroy := cells.DestroyCell{
		CircuitID: torConn.CircuitID,
		Reason:    0,
	}

	_, err = torConn.Conn.Write(cellDestroy.Serialize())
	torConn.Conn.Close()

	return con, err
}
