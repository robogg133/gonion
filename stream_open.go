package gonion

import (
	"context"
	"errors"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (s *Stream) beginDir() error {

	select {
	case s.circuit.WriteRelayCell <- struct {
		relay.Cell
		uint8
	}{Cell: &relay.BeginDirCell{StreamID: s.ID}, uint8: s.myHopDestination}:
	case <-s.Ctx.Done():
		return context.Cause(s.Ctx)
	}

	select {
	case relayCell := <-s.InboundControl:
		if relayCell.ID() != relay.COMMAND_CONNECTED {
			return errors.New("the relay didn't responded the BEGIN_DIR cell with a CONNECTED")
		}
	case <-s.Ctx.Done():
		return context.Cause(s.Ctx)
	}
	return nil
}
