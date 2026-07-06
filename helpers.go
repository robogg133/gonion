package gonion

import (
	"context"
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

func (c *Circuit) sendmeManage(i int, window *window.Window, ctx context.Context) {
	for {
		select {
		case digest := <-window.Get():
			sendMeCell := &relay.SendMeCell{
				StreamID:        0,
				Version:         c.SendMeVersion,
				Sha1ForLastCell: digest,
			}
			select {
			case c.WriteRelayCell <- struct {
				relay.Cell
				uint8
			}{Cell: sendMeCell, uint8: uint8(i)}:
				window.Increase()
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Circuit) deleteHop(i int) {
	c.hops = remove(c.hops, i)
	c.hopsWindows = remove(c.hopsWindows, i)
	c.hopsCtx = remove(c.hopsCtx, i)
}

func remove[T any](s []T, i int) []T {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}
