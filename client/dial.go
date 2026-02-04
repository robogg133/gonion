package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/robogg133/gonion/circuit"
	"github.com/robogg133/gonion/connection"
	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/shared"
	"github.com/robogg133/gonion/tor_crypto"
)

type ClientConfig struct {
	GetStable bool
}

func Dial(address string, cfg *ClientConfig) error {

	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}

	cons := shared.GetGlobalConsensus()

	if cons == nil {
		fallback, err := connection.SelectFirstFromFallBackAnonPorts()
		if err != nil {
			return err
		}
		cons, err = circuit.ConnectToRelayAndGetConsensus(fallback.IPv4, fallback.ORPort)
		if err != nil {
			return err
		}
		shared.SetGlobalConsensus(*cons)
	}

	exit := circuit.SelectExitRelay(addr.Port(), cons, cfg.GetStable)
	guard := circuit.SelectGuardRelay(cons, exit.IPLevel)
	middle := circuit.SellectMiddleRelay(cons, exit.IPLevel, guard.IPLevel, cfg.GetStable)

	guardConn, err := connection.OpenConnection(guard.Ipv4Addr, guard.ORPort)
	if err != nil {
		return err
	}
	fmt.Println("DONE")

	guardConn.CircuitID = cells.MSB(1)
	guardConn.RelayStreamID = 1
	xMaterial, err := guardConn.SendCreateFast()
	if err != nil {
		return err
	}
	fmt.Println("DONE")

	createdFast, err := guardConn.ReadCreatedFast()
	if err != nil {
		return err
	}
	fmt.Println("DONE")

	keys, err := tor_crypto.DeriveKeysCreateFast(xMaterial, createdFast.Y)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("DONE")

	if !bytes.Equal(keys.KH, createdFast.KH[:]) {
		return fmt.Errorf("KH key don't match")
	}

	guardConn.ForwardDigest = sha1.New()
	guardConn.ForwardDigest.Write(keys.Df)

	guardConn.BackWardsDigest = sha1.New()
	guardConn.BackWardsDigest.Write(keys.Db)

	block, err := aes.NewCipher(keys.Kf)
	if err != nil {
		log.Fatal(err)
	}
	tmp := make([]byte, 16)
	guardConn.KeyForwardAES128CTR = cipher.NewCTR(block, tmp)

	block2, err := aes.NewCipher(keys.Kb)
	if err != nil {
		log.Fatal(err)
	}
	tmp = make([]byte, 16)
	guardConn.KeyBackwardsAES128CTR = cipher.NewCTR(block2, tmp)

	if err := guardConn.SendRelayBeginDir(); err != nil {
		return err
	}
	fmt.Println("DONE")

	if err := guardConn.ReadRelayCell(); err != nil {
		return err
	}
	fmt.Println("DONE")

	guardDigestSerialized := base64.RawStdEncoding.EncodeToString(guard.Digest[:])
	middleDigestSerialized := base64.RawStdEncoding.EncodeToString(middle.Digest[:])
	exitDigestSerialized := base64.RawStdEncoding.EncodeToString(exit.Digest[:])
	if err := guardConn.SendRelayGetMicrodescriptors(guardDigestSerialized, middleDigestSerialized, exitDigestSerialized); err != nil {
		return err
	}

	data, err := guardConn.ReadRelayData()
	if err != nil {
		return err
	}
	fmt.Println("DONE")

	fmt.Println(string(data))

	if strings.HasSuffix(address, ".onion") {
		// Need to implement .onion address solve
	}
	return nil
}
