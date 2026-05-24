package gonion

import (
	"errors"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (s *Stream) beginDir() error {

	s.circuit.WriteRelayCell <- &relay.BeginDirCell{StreamID: s.ID}

	relayCell := <-s.InboundControl
	if relayCell.ID() != relay.COMMAND_CONNECTED {
		return errors.New("the relay didn't responded the BEGIN_DIR cell with a CONNECTED")
	}
	return nil
}
