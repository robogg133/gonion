package connection

import (
	"bytes"
	"io"

	"github.com/robogg133/gonion/connection/cells"
	"github.com/robogg133/gonion/relay"
)

const (
	PAYLOAD_GET_DIRECTORY_INFO   string = "GET /tor/server/authority HTTP/1.0\r\n\r\n"
	PAYLOAD_GET_CONSENSUS        string = "GET /tor/status-vote/current/consensus HTTP/1.0\r\n\r\n"
	PAYLOAD_GET_MICRODESCRIPTORS string = "GET /tor/micro/d/%s-%s-%s HTTP/1.0\r\n\r\n"
)

func (t *TORConnection) SendRelayBeginDir() error {

	t.RelayStreamID = 1

	relayRelayCell := relay.BeginDir{
		StreamID:     t.RelayStreamID,
		DigestWriter: &t.ForwardDigest,
	}

	relayCell := cells.RelayCell{
		CircuitID: t.CircuitID,
		RelayCell: relayRelayCell.Serialize(),
	}

	_, err := t.Conn.Write(relayCell.Serialize(t.KeyForwardAES128CTR))
	return err
}

func (t *TORConnection) ReadRelayCell() error {

	c := make([]byte, 514)
	io.ReadFull(t.Conn, c)

	return cells.RelayCheckIfConnected(c, &t.KeyBackwardsAES128CTR, t.BackWardsDigest)
}

func (t *TORConnection) SendRelayGetDirectory() error {
	rc := relay.DataCell{
		StreamID:     t.RelayStreamID,
		DigestWriter: t.ForwardDigest,
		Payload:      []byte(PAYLOAD_GET_DIRECTORY_INFO),
	}

	c := cells.RelayCell{
		CircuitID: t.CircuitID,
		RelayCell: rc.Serialize(),
	}

	_, err := t.Conn.Write(c.Serialize(t.KeyForwardAES128CTR))

	return err
}

func (t *TORConnection) SendRelayGetConsensus() error {
	rc := relay.DataCell{
		StreamID:     t.RelayStreamID,
		DigestWriter: t.ForwardDigest,
		Payload:      []byte(PAYLOAD_GET_CONSENSUS),
	}

	c := cells.RelayCell{
		CircuitID: t.CircuitID,
		RelayCell: rc.Serialize(),
	}

	_, err := t.Conn.Write(c.Serialize(t.KeyForwardAES128CTR))

	return err
}

func (t *TORConnection) ReadRelayData() ([]byte, error) {

	i := 1
	var result bytes.Buffer
	for {
		if i == 50 {
			rc := relay.SendMeCell{
				StreamID:        t.RelayStreamID,
				Sha1ForLastCell: [20]byte(t.BackWardsDigest.Sum(nil)),
				Forward:         t.ForwardDigest,
			}

			c := cells.RelayCell{
				CircuitID: t.CircuitID,
				RelayCell: rc.Serialize(),
			}

			_, err := t.Conn.Write(c.Serialize(t.KeyForwardAES128CTR))
			if err != nil {
				return nil, err
			}
			i = 0
		}

		if t.CircuitChannelPackets == 100 {
			rc := relay.SendMeCell{
				StreamID:        0,
				Sha1ForLastCell: [20]byte(t.BackWardsDigest.Sum(nil)),
				Forward:         t.ForwardDigest,
			}

			c := cells.RelayCell{
				CircuitID: t.CircuitID,
				RelayCell: rc.Serialize(),
			}

			_, err := t.Conn.Write(c.Serialize(t.KeyForwardAES128CTR))
			if err != nil {
				return nil, err
			}
			t.CircuitChannelPackets = 0
		}

		buffer := make([]byte, 514)
		_, err := io.ReadFull(t.Conn, buffer)
		if err != nil {
			return nil, err
		}
		t.CircuitChannelPackets++

		cell, err := cells.ReadDataCell(buffer, t.KeyBackwardsAES128CTR, t.BackWardsDigest)
		if err != nil {
			if err == relay.ErrRelayEnd {
				break
			}
			return nil, err
		}

		if cell.CircuitID != t.CircuitID {
			return nil, err
		}

		result.Write(cell.RelayCell)
		i++
	}

	return result.Bytes(), nil
}
