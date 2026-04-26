package gonion

import (
	"bytes"

	cells "git.servidordomal.fun/robogg133/gonion/pkg/cells/base"
	"git.servidordomal.fun/robogg133/gonion/pkg/cells/relay"
)

func (c *Circuit) readloop() {
	for {
		// Check circuit receive window and send SENDME if needed
		c.ReceiveWindow.mu.Lock()
		if c.ReceiveWindow.v%100 == 0 && c.ReceiveWindow.v != 1000 {
			cell := &cells.RelayCell{
				RelayCoder: c.Coder.RelayCoder,
				Cell: &relay.SendMeCell{
					StreamID:        0,
					Version:         c.SendMeVersion,
					Sha1ForLastCell: c.Backwards.GetLastSumDataCell(),
				},
			}
			if err := c.SendCell(cell); err != nil {
				c.ReceiveWindow.mu.Unlock()
				c.Close()
				return
			}
			c.ReceiveWindow.v += 100
		}
		c.ReceiveWindow.mu.Unlock()

		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				c.Close()
				return
			}

			if cell.ID() == cells.COMMAND_RELAY {
				relaycell := cell.(*cells.RelayCell).Cell

				if relaycell.GetStreamID() == 0 && relaycell.ID() == relay.COMMAND_SENDME {
					c.SendWindow.Add(100)
					continue
				}

				stream := c.streams.Get(relaycell.GetStreamID())
				if stream == nil {
					continue
				}
				select {
				case stream.Inbound <- relaycell:
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
