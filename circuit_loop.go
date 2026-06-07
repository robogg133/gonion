package gonion

import (
	"bytes"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (c *Circuit) readloop() {
	for {
		// Check circuit receive window and send SENDME if needed
		if c.ReceiveWindow.Check() {
			cell := &cells.RelayCell{
				RelayCoder: c.Coder.RelayCoder,
				Cell: &relay.SendMeCell{
					StreamID:        0,
					Version:         c.SendMeVersion,
					Sha1ForLastCell: c.Backwards.GetLastSumDataCell(),
				},
			}
			if err := c.SendCell(cell); err != nil {
				c.Close()
				return
			}
			c.ReceiveWindow.Add(100)
		}

		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				c.Close()
				return
			}

			// Check if is relay cell
			if cell.ID() == cells.COMMAND_RELAY {
				relaycell := cell.(*cells.RelayCell).Cell

				if relaycell.GetStreamID() == 0 {
					c.relayControlFunc(relaycell)
					continue
				}

				stream := c.streams.Get(relaycell.GetStreamID())
				if stream == nil {
					continue
				}

				if relaycell.ID() == relay.COMMAND_DATA {
					c.ReceiveWindow.Subtract(1)
					if err := stream.writeDataCell(relaycell.(*relay.DataCell)); err != nil {
						stream.Close()
					}
					continue
				}

				select {
				case stream.InboundControl <- relaycell:
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
		case relayCell := <-c.WriteRelayCell:
			if relayCell.ID() == relay.COMMAND_DATA {
				c.SendWindow.Subtract(1)

				if c.SendWindow.Get() == 0 {
					select {
					case <-c.sendMeReceived:
						c.SendWindow.Increase()
					case <-c.CloseCh:
						return
					}
				}
			}
			cell := &cells.RelayCell{
				RelayCoder: c.Coder.RelayCoder,
				Cell:       relayCell,
			}
			c.SendCell(cell)

		case <-c.CloseCh:
			c.Close()
			return
		}
	}
}

func (c *Circuit) relayControlFunc(rc relay.Cell) {
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
