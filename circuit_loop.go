package gonion

import (
	"bytes"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (c *Circuit) readloop() {
	log := logger(c.Ctx)
	log.Debug().Msg("circuit read loop started")
	defer log.Debug().Msg("circuit read loop stopped")

	for {
		select {
		case rawCell := <-c.Inbound:
			cell, err := c.Coder.ReadCell(bytes.NewReader(rawCell))
			if err != nil {
				pub := fail(c.Ctx, ErrIO, "decode inbound cell failed", err)
				c.ctxCancel(pub)
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
					log.Error().Err(err).Msg("onion decrypt failed")
					pub := fail(c.Ctx, ErrDecrypt, "relay decrypt failed", err)
					c.ctxCancel(pub)
					return
				}

				if rcCell.GetStreamID() == 0 {
					c.relayControlFunc(rcCell, hopN)
					continue
				}

				stream := c.streams.Get(rcCell.GetStreamID())
				if stream == nil {
					log.Debug().
						Uint16("stream_id", rcCell.GetStreamID()).
						Uint8("relay_cmd", rcCell.ID()).
						Int("hop", hopN).
						Msg("relay cell for unknown stream dropped")
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
						logger(stream.Ctx).Warn().Err(err).Msg("stream buffer write failed")
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
	log := logger(c.Ctx)
	log.Debug().Msg("circuit write loop started")
	defer log.Debug().Msg("circuit write loop stopped")

	for {
		select {
		case out := <-c.WriteRelayCell:
			body, err := c.hops.MarshalMessage(out.Cell, out.Dst)
			if err != nil {
				log.Error().Err(err).Int("dst", out.Dst).Uint8("relay_cmd", out.Cell.ID()).Msg("onion encrypt failed")
				pub := fail(c.Ctx, ErrCircuit, "relay encrypt failed", err)
				c.ctxCancel(pub)
				return
			}

			if out.Cell.ID() == relay.COMMAND_DATA {
				hop := c.hops.At(out.Dst)
				if hop == nil {
					pub := failf(c.Ctx, ErrInvalidHop, nil, "invalid hop destination %d", out.Dst)
					c.ctxCancel(pub)
					return
				}
				sendWindow := hop.Send()
				sendWindow.SetDigest(out.Cell.(*relay.DataCell).Digest())
				sendWindow.Subtract(1)
				if sendWindow.IsZero() {
					log.Debug().Int("hop", out.Dst).Msg("circuit send window exhausted, waiting SENDME")
					select {
					case <-hop.SendMe():
						sendWindow.Increase()
						log.Debug().Int("hop", out.Dst).Msg("circuit send window restored")
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
	log := logger(c.Ctx).With().Int("hop", dst).Uint8("relay_cmd", rc.ID()).Logger()

	switch rc.ID() {
	case relay.COMMAND_SENDME:
		hop := c.hops.At(dst)
		if hop == nil {
			pub := failf(c.Ctx, ErrInvalidHop, nil, "invalid hop destination %d", dst)
			c.ctxCancel(pub)
			return
		}
		if err := verifySendMe(c.Ctx, rc.(*relay.SendMeCell), c.SendMeVersion, hop.Send()); err != nil {
			c.ctxCancel(err)
			return
		}
		log.Debug().Msg("circuit SENDME accepted")
		hop.NotifySendMe()
	case relay.COMMAND_EXTENDED2:
		log.Debug().Msg("EXTENDED2 received")
		select {
		case c.extended2Received <- rc.(*relay.Extended2Cell):
		case <-c.Ctx.Done():
		default:
			log.Warn().Msg("EXTENDED2 dropped (no waiter)")
		}
	case relay.COMMAND_RENDEZVOUS_ESTABLISHED, relay.COMMAND_RENDEZVOUS2,
		relay.COMMAND_INTRO_ESTABLISHED, relay.COMMAND_INTRODUCE_ACK:
		// Hidden-service control cells have no stream ID. If a hidden-service
		// op registered a handler, forward non-blocking; otherwise keep the
		// existing debug log below.
		if c.HSControl != nil {
			select {
			case c.HSControl <- rc:
			case <-c.Ctx.Done():
			default:
				log.Warn().Uint8("relay_cmd", rc.ID()).Msg("HS control cell dropped (no waiter)")
			}
			return
		}
		log.Debug().Msg("unhandled circuit control relay")
	default:
		log.Debug().Msg("unhandled circuit control relay")
	}
}
