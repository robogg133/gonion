package gonion

import (
	"bytes"
	"fmt"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (c *Circuit) readloop() {
	for {
		// Check circuit receive window and send SENDME if needed
		for i, window := range c.hopsWindows {
			select {
			case digest := <-window.receive.Get():

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
					window.receive.Increase()
				case <-c.Ctx.Done():
				}
			default:
			}
		}
		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				c.ctxCancel(err)
				return
			}

			// Check if is relay cell
			if cell.ID() == cells.COMMAND_RELAY {
				relaycell := cell.(*cells.RelayCell)
				rcCell := relaycell.Cell

				if rcCell.GetStreamID() == 0 {
					c.relayControlFunc(rcCell, relaycell.HopDestination())
					continue
				}

				stream := c.streams.Get(rcCell.GetStreamID())
				if stream == nil {
					continue
				}

				if rcCell.ID() == relay.COMMAND_DATA {
					dataCell := rcCell.(*relay.DataCell)
					c.hopsWindows[relaycell.HopDestination()].receive.SetDigest(dataCell.Digest())
					c.hopsWindows[relaycell.HopDestination()].receive.Subtract(1) // Subtract from receive window

					if err := stream.writeDataCell(dataCell); err != nil {
						stream.Close()
					}
					continue
				}

				select {
				case stream.InboundControl <- rcCell:
				case <-stream.Ctx.Done():
				}
				continue
			}

			// Non-relay cells (DESTROY, etc.)
			go c.handleCell(cell)
		case <-c.Ctx.Done():
			return
		}
	}
}

func (c *Circuit) writeLoop() {
	for {
		select {
		case cll := <-c.WriteRelayCell:
			if cll.Cell.ID() == relay.COMMAND_DATA {
				sendWindow := c.hopsWindows[cll.uint8].send
				sendWindow.SetDigest(cll.Cell.(*relay.DataCell).Digest())
				sendWindow.Subtract(1)
				if sendWindow.IsZero() {
					select {
					case <-c.sendMeReceived:
						sendWindow.Increase()
					case <-c.Ctx.Done():
						return
					}
				}
			}
			cell := &cells.RelayCell{
				Hops: c.hops[0 : cll.uint8+1],
				Cell: cll.Cell,
			}
			c.SendCell(cell)

		case <-c.Ctx.Done():
			return
		}
	}
}

func (c *Circuit) relayControlFunc(rc relay.Cell, dst uint8) {
	switch rc.ID() {
	case relay.COMMAND_SENDME:
		if err := verifySendMe(rc.(*relay.SendMeCell), c.SendMeVersion, c.hopsWindows[dst].send); err != nil {
			c.ctxCancel(err)
			return
		}
		select {
		case c.sendMeReceived <- struct{}{}:
		default:
		}
	case relay.COMMAND_EXTENDED2:
		select {
		case c.extended2Received <- rc.(*relay.Extended2Cell):
		default:
			fmt.Println("sended extended2received signal but no one was listening")
			// why no one is listening??
		}
	}

}
