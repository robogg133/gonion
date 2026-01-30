package connection

import (
	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/relay"
)

func (t *TORConnection) SendRelayBeginDir() error {

	relayRelayCell := relay.BeginDir{
		StreamID:     1,
		DigestWriter: &t.ForwardDigest,
	}

	relayCell := cells.RelayCell{
		CircuitID: t.CircuitID,
		RelayCell: relayRelayCell.Serialize(),
	}

	_, err := t.Conn.Write(relayCell.Serialize(&t.KeyForwardAES128CTR))
	return err
}

func (t *TORConnection) ReadRelayCell() error {

	c := make([]byte, 514)
	if _, err := t.Conn.Read(c); err != nil {
		return err
	}

	return cells.RelayCheckIfConnected(c, &t.KeyBackwardsAES128CTR, &t.BackWardsDigest)
}
