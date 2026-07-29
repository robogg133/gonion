package gonion

import (
	"context"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

func (s *Stream) beginDir() error {
	log := logger(s.Ctx)
	log.Debug().Msg("sending BEGIN_DIR")

	select {
	case s.circuit.WriteRelayCell <- RelayOut{Cell: &relay.BeginDirCell{StreamID: s.ID}, Dst: s.myHopDestination}:
	case <-s.Ctx.Done():
		return fail(s.Ctx, ErrStream, "stream closed before BEGIN_DIR", context.Cause(s.Ctx))
	}

	select {
	case relayCell := <-s.InboundControl:
		if relayCell.ID() != relay.COMMAND_CONNECTED {
			log.Error().Uint8("cmd", relayCell.ID()).Msg("BEGIN_DIR expected CONNECTED")
			return Publicf(ErrStream, "BEGIN_DIR failed: expected CONNECTED, got command %d", relayCell.ID())
		}
		log.Debug().Msg("BEGIN_DIR connected")
	case <-s.Ctx.Done():
		return fail(s.Ctx, ErrStream, "stream closed waiting CONNECTED", context.Cause(s.Ctx))
	}
	return nil
}

func (s *Stream) begin(addrport string) error {
	log := logger(s.Ctx)
	log.Debug().Str("addrport", addrport).Msg("sending BEGIN")

	select {
	case s.circuit.WriteRelayCell <- RelayOut{
		Cell: &relay.BeginCell{Addrport: addrport, StreamID: s.ID},
		Dst:  s.myHopDestination,
	}:
	case <-s.Ctx.Done():
		return fail(s.Ctx, ErrStream, "stream closed before BEGIN", context.Cause(s.Ctx))
	}

	select {
	case relayCell := <-s.InboundControl:
		if relayCell.ID() != relay.COMMAND_CONNECTED {
			if end, ok := relayCell.(*relay.RelayEndCell); ok {
				log.Error().Uint8("reason", end.Reason).Msg("BEGIN rejected with RELAY_END")
				return Publicf(ErrStream, "BEGIN rejected: %s", relay.EndReasonString(end.Reason))
			}
			log.Error().Uint8("cmd", relayCell.ID()).Msg("BEGIN expected CONNECTED")
			return Publicf(ErrStream, "BEGIN failed: expected CONNECTED, got command %d", relayCell.ID())
		}
		log.Debug().Msg("BEGIN connected")
	case <-s.Ctx.Done():
		return fail(s.Ctx, ErrStream, "stream closed waiting CONNECTED", context.Cause(s.Ctx))
	}
	return nil
}
