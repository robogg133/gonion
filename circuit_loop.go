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
			if window.receive.Check() {
				cell := &cells.RelayCell{
					CircuitID: c.ID,
					Hops:      c.hops[0 : i+1],
					Cell: &relay.SendMeCell{
						StreamID:        0,
						Version:         c.SendMeVersion,
						Sha1ForLastCell: c.hops[i].Backwards.GetLastSumDataCell(),
					},
				}
				if err := c.SendCell(cell); err != nil {
					fmt.Println(err)
					c.Close()
					return
				}
				window.receive.Increase()
			}
		}
		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				fmt.Println(err)
				c.Close()
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
					c.hopsWindows[relaycell.HopDestination()].receive.Subtract(1) // Subtract from receive window
					if err := stream.writeDataCell(rcCell.(*relay.DataCell)); err != nil {
						stream.Close()
					}
					continue
				}

				select {
				case stream.InboundControl <- rcCell:
				case <-stream.CloseCh:
				}
				continue
			}

			// Non-relay cells (DESTROY, etc.)
			go c.handleCell(cell)
		case <-c.CloseCh:
			c.Close()
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
				sendWindow.Subtract(1)

				if sendWindow.Get() == 0 {
					select {
					case <-c.sendMeReceived:
						sendWindow.Increase()
					case <-c.CloseCh:
						return
					}
				}
			}
			cell := &cells.RelayCell{
				Hops: c.hops[0 : cll.uint8+1],
				Cell: cll.Cell,
			}
			c.SendCell(cell)

		case <-c.CloseCh:
			c.Close()
			return
		}
	}
}

func (c *Circuit) relayControlFunc(rc relay.Cell, _ uint8) {
	switch rc.ID() {
	case relay.COMMAND_SENDME:
		select {
		case c.sendMeReceived <- struct{}{}:
		default:
		}
	case relay.COMMAND_EXTENDED2:
		select {
		case c.extended2Received <- rc.(*relay.Extended2Cell):
		default:
			// why no one is listening??
		}
	}

}
