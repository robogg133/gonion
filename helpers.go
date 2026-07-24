package gonion

import (
	"fmt"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/window"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func verifySendMe(sendme *relay.SendMeCell, sendmeVersion uint8, win *window.Window) error {
	if sendmeVersion == 0 {
		return nil
	}
	if sendme.Version != sendmeVersion {
		return fmt.Errorf("protocol violation: different SEND_ME version")
	}

	select {
	case digest := <-win.Get():
		if digest != sendme.Sha1ForLastCell {
			return fmt.Errorf("protocol violation mismatched SEND_ME digest: %x %x", sendme.Sha1ForLastCell[:], digest[:])
		}
	default:
		return fmt.Errorf("protocol violation: unexpected SEND_ME")
	}
	return nil
}

func (c *Circuit) sendmeManage(i int, hop *hops.Hop) {
	win := hop.Recv()
	ctx := hop.Ctx()
	for {
		select {
		case digest := <-win.Get():
			sendMeCell := &relay.SendMeCell{
				StreamID:        0,
				Version:         c.SendMeVersion,
				Sha1ForLastCell: digest,
			}
			select {
			case c.WriteRelayCell <- RelayOut{Cell: sendMeCell, Dst: i}:
				win.Increase()
			case <-ctx.Done():
				return
			case <-c.Ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		case <-c.Ctx.Done():
			return
		}
	}
}
