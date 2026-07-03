package gonion

import (
	"fmt"

	"github.com/robogg133/gonion/internal/window"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func verifySendMe(sendme *relay.SendMeCell, sendmeVersion uint8, window *window.Window) error {
	if sendmeVersion == 0 {
		return nil
	}
	if sendme.Version != sendmeVersion {
		return fmt.Errorf("protocol violation: different SEND_ME version")
	}

	select {
	case digest := <-window.Get():
		if digest != sendme.Sha1ForLastCell {
			return fmt.Errorf("protcol violation mismatched SEND_ME digest: %x %x", sendme.Sha1ForLastCell[:], digest[:])
		}
	default:
		return fmt.Errorf("protocol violation: unexpected SEND_ME")
	}
	return nil
}
