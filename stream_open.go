package gonion2

import (
	"errors"

	"git.servidordomal.fun/robogg133/gonion-rewrite/pkg/cells/relay"
)

func (s *Stream) beginDir() error {

	s.circuit.WriteRelayCell <- &relay.BeginDirCell{StreamID: s.ID}

	relayCell := <-s.Inbound
	if relayCell.ID() != relay.COMMAND_CONNECTED {
		return errors.New("the relay didn't responded the BEGIN_DIR cell with a CONNECTED")
	}
	return nil
}
