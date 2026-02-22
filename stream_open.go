package gonion

import (
	"errors"
	"fmt"

	"github.com/robogg133/gonion/relay"
)

func (s *Stream) beginDir() error {

	fmt.Println("==> Sending to circuit write order")
	s.circuit.WriteRelayCell <- &relay.BeginDir{StreamID: s.ID}
	fmt.Println("==> Write order sent")
	relayCell := <-s.Inbound
	fmt.Println("==> Got a relay cell")
	if relayCell.ID() != relay.COMMAND_CONNECTED {
		return errors.New("the relay didn't responded the BEGIN_DIR cell with a CONNECTED")
	}
	fmt.Println("==> DIR OPENED")
	return nil
}
