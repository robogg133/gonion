package gonion

import (
	"bytes"
	"fmt"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (c *Circuit) readloop() {
	for {
		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				c.ctxCancel(err)
				return
			}

			switch cell.ID() {
			case cells.COMMAND_RELAY, cells.COMMAND_RELAY_EARLY:
				var body []byte
				switch rc := cell.(type) {
				case *cells.RelayCell:
					body = rc.Body
				case *cells.RelayEarlyCell:
					body = rc.C.Body
				}

				hopN, rcCell, err := c.hops.UnmarshalMessage(body)
				if err != nil {
					c.ctxCancel(err)
					return
				}

				if rcCell.GetStreamID() == 0 {
					c.relayControlFunc(rcCell, hopN)
					continue
				}

				stream := c.streams.Get(rcCell.GetStreamID())
				if stream == nil {
					continue
				}

				if rcCell.ID() == relay.COMMAND_DATA {
					dataCell := rcCell.(*relay.DataCell)
					hop := c.hops.At(hopN)
					if hop != nil {
						hop.Recv().SetDigest(dataCell.Digest())
						hop.Recv().Subtract(1)
					}
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

			default:
				go c.handleCell(cell)
			}
		case <-c.Ctx.Done():
			return
		}
	}
}

func (c *Circuit) writeLoop() {
	for {
		select {
		case out := <-c.WriteRelayCell:
			body, err := c.hops.MarshalMessage(out.Cell, out.Dst)
			if err != nil {
				c.ctxCancel(err)
				return
			}

			if out.Cell.ID() == relay.COMMAND_DATA {
				hop := c.hops.At(out.Dst)
				if hop == nil {
					c.ctxCancel(errInvalidHop(out.Dst))
					return
				}
				sendWindow := hop.Send()
				sendWindow.SetDigest(out.Cell.(*relay.DataCell).Digest())
				sendWindow.Subtract(1)
				if sendWindow.IsZero() {
					select {
					case <-hop.SendMe():
						sendWindow.Increase()
					case <-c.Ctx.Done():
						return
					case <-hop.Ctx().Done():
						return
					}
				}
			}

			if err := c.SendCell(&cells.RelayCell{Body: body}); err != nil {
				return
			}

		case <-c.Ctx.Done():
			return
		}
	}
}

func (c *Circuit) relayControlFunc(rc relay.Cell, dst int) {
	switch rc.ID() {
	case relay.COMMAND_SENDME:
		hop := c.hops.At(dst)
		if hop == nil {
			c.ctxCancel(errInvalidHop(dst))
			return
		}
		if err := verifySendMe(rc.(*relay.SendMeCell), c.SendMeVersion, hop.Send()); err != nil {
			c.ctxCancel(err)
			return
		}
		hop.NotifySendMe()
	case relay.COMMAND_EXTENDED2:
		select {
		case c.extended2Received <- rc.(*relay.Extended2Cell):
		case <-c.Ctx.Done():
		default:
		}
	}
}

func errInvalidHop(dst int) error {
	return fmt.Errorf("invalid hop destination: %d", dst)
}
