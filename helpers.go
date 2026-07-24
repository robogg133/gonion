package gonion

import (
	"context"
	"encoding/hex"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/window"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

func verifySendMe(ctx context.Context, sendme *relay.SendMeCell, sendmeVersion uint8, win *window.Window) error {
	if sendmeVersion == 0 {
		return nil
	}
	if sendme.Version != sendmeVersion {
		logger(ctx).Error().
			Uint8("got", sendme.Version).
			Uint8("want", sendmeVersion).
			Msg("SENDME version mismatch")
		return Public(ErrSendMe, "version mismatch")
	}

	select {
	case digest := <-win.Get():
		if digest != sendme.Sha1ForLastCell {
			// Digests stay in logs only — not in the public error string.
			logger(ctx).Error().
				Str("got", hex.EncodeToString(sendme.Sha1ForLastCell[:])).
				Str("want", hex.EncodeToString(digest[:])).
				Msg("SENDME digest mismatch")
			return Public(ErrSendMe, "digest mismatch")
		}
	default:
		logger(ctx).Error().Msg("unexpected SENDME")
		return Public(ErrSendMe, "unexpected")
	}
	return nil
}

func (c *Circuit) sendmeManage(i int, hop *hops.Hop) {
	win := hop.Recv()
	ctx := hop.Ctx()
	log := logger(c.Ctx).With().Int("hop", i).Str("job", "sendme_manage").Logger()
	log.Debug().Msg("sendme manager started")
	defer log.Debug().Msg("sendme manager stopped")

	for {
		select {
		case digest := <-win.Get():
			sendMeCell := &relay.SendMeCell{
				StreamID:        0,
				Version:         c.SendMeVersion,
				Sha1ForLastCell: digest,
			}
			select {
			case c.WriteRelayCell <- RelayOut{Cell: sendMeCell, Dst: i}:
				win.Increase()
				log.Debug().Msg("circuit SENDME sent")
			case <-ctx.Done():
				return
			case <-c.Ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		case <-c.Ctx.Done():
			return
		}
	}
}
