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
					if rcCell.ID() == relay.COMMAND_BEGIN || rcCell.ID() == relay.COMMAND_DATA || rcCell.ID() == relay.COMMAND_CONNECTED {
						c.ctxCancel(Public(ErrProtocolViolation, "stream command has zero stream ID"))
						return
					}
					c.relayControlFunc(rcCell, hopN)
					continue
				}

				if data, ok := rcCell.(*relay.DataCell); ok {
					hop := c.hops.At(hopN)
					if hop == nil || hop.Recv().Value() <= 0 {
						c.ctxCancel(Public(ErrProtocolViolation, "circuit receive window exceeded"))
						return
					}
					hop.Recv().SetDigest(data.Digest())
					hop.Recv().Subtract(1)
				}
				if begin, ok := rcCell.(*relay.BeginCell); ok {
					c.acceptIncomingBegin(begin, hopN)
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

				if stream.myHopDestination != hopN {
					c.ctxCancel(Public(ErrProtocolViolation, "stream cell recognized by wrong hop"))
					return
				}
				if rcCell.ID() == relay.COMMAND_DATA {
					dataCell := rcCell.(*relay.DataCell)

					if err := stream.writeDataCell(dataCell); err != nil {
						logger(stream.Ctx).Warn().Err(err).Msg("stream buffer write failed")
						c.ctxCancel(Public(ErrProtocolViolation, "stream receive buffer or window exceeded"))
						return
					}
					continue
				}

				select {
				case stream.InboundControl <- rcCell:
				case <-stream.Ctx.Done():
				default:
					c.ctxCancel(Public(ErrProtocolViolation, "stream control queue exceeded"))
					return
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

	sendControl := func(out RelayOut) bool {
		if err := c.sendRelay(out.Cell, out.Dst, false); err != nil {
			c.ctxCancel(err)
			return false
		}
		return true
	}
	for {
		select {
		case control := <-c.writeControl:
			if !sendControl(control) {
				return
			}
		case out := <-c.WriteRelayCell:
			if out.Cell.ID() == relay.COMMAND_DATA {
				hop := c.hops.At(out.Dst)
				if hop == nil {
					c.ctxCancel(ErrInvalidHop)
					return
				}
				for hop.Send().IsZero() {
					select {
					case <-hop.SendMe():
					case control := <-c.writeControl:
						if !sendControl(control) {
							return
						}
					case <-c.Ctx.Done():
						return
					}
				}
			}
			err := c.sendRelay(out.Cell, out.Dst, false)
			if out.sent != nil {
				out.sent <- err
			}
			if err != nil {
				log.Error().Err(err).Int("dst", out.Dst).Uint8("relay_cmd", out.Cell.ID()).Msg("onion encrypt failed")
				pub := fail(c.Ctx, ErrCircuit, "relay encrypt failed", err)
				c.ctxCancel(pub)
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
		hop.Send().Increase()
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
		relay.COMMAND_INTRO_ESTABLISHED, relay.COMMAND_INTRODUCE_ACK, relay.COMMAND_INTRODUCE2:
		if dst != c.hops.Len()-1 || rc.GetStreamID() != 0 {
			c.ctxCancel(Public(ErrProtocolViolation, "HS control recognized by wrong hop"))
			return
		}
		c.controlMu.RLock()
		ch := c.HSControl
		c.controlMu.RUnlock()
		if ch == nil {
			c.ctxCancel(Public(ErrProtocolViolation, "unsolicited HS control cell"))
			return
		}
		select {
		case ch <- rc:
		case <-c.Ctx.Done():
		default:
			c.ctxCancel(Public(ErrProtocolViolation, "HS control queue exhausted"))
		}
	default:
		log.Debug().Msg("unhandled circuit control relay")
	}
}
