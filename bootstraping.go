package gonion

import (
	"context"
	"crypto/ecdh"
	"math/rand"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

// nextConsensus will refresh the consensus when needed
func (circuit *Circuit) nextConsensus(ctx context.Context, cns *common.Consensus) {
	log := logger(ctx).With().Str("job", "consensus_refresh").Logger()

	select {
	case <-ctx.Done():
		return
	default:
	}

	minutesBetweenFreshAndValid := (cns.FreshUntil.Hour() - cns.ValidAfter.Hour()) * 60

	minutes := (time.Duration(minutesBetweenFreshAndValid) / 4) * 3 * time.Minute
	start := cns.FreshUntil.Add(minutes)

	minutesBetweenFreshAndUnvalid := (cns.ValidUntil.Hour() - cns.FreshUntil.Hour()) * 60
	minutes = (time.Duration(minutesBetweenFreshAndUnvalid) / 8) * 7 * time.Minute
	end := cns.FreshUntil.Add(minutes)

	ns := start.Unix()
	ne := end.Unix()

	fetchTimestamp := rand.Int63n(ne-ns) + ns
	fetchTime := time.Unix(fetchTimestamp, 0).UTC()

	log.Info().Time("fetch_at", fetchTime).Msg("scheduled consensus refresh")

	if err := sleepCtx(ctx, time.Until(fetchTime)); err != nil {
		log.Debug().Err(err).Msg("consensus refresh cancelled")
		return
	}

	cnsPtr, err := circuit.GetConsensus()
	if err != nil {
		log.Error().Err(err).Msg("consensus refresh failed")
		return
	}

	*cns = *cnsPtr
	log.Info().Int("relays", len(cns.RelayInformation)).Msg("consensus refreshed")

	go circuit.nextConsensus(ctx, cns)
}

// BootstrapOneConn fetches consensus and microdescriptors using one OR connection.
func BootstrapOneConn(conn *Conn) error {
	ctx := conn.ctx
	log := logger(ctx).With().Str("job", "bootstrap").Logger()
	ctx = withLogger(ctx, log)
	log.Info().Msg("bootstrap starting")

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		return fail(ctx, ErrBootstrap, "create bootstrap circuit failed", err)
	}

	cns, err := circuit.GetConsensus()
	if err != nil {
		return fail(ctx, ErrBootstrap, "fetch consensus failed", err)
	}
	log.Info().Int("relays", len(cns.RelayInformation)).Msg("consensus fetched")

	common.SetGlobalConsensus(cns)

	var allDigests []string
	for _, relay := range cns.RelayInformation {
		allDigests = append(allDigests, relay.MicrodescriptorDigest)
	}

	for i := 0; i < len(allDigests); i += 91 {
		end := i + 91
		end = min(end, len(allDigests))
		chunk := allDigests[i:end]
		log.Debug().Int("offset", i).Int("count", len(chunk)).Msg("fetching microdescriptor chunk")
		if err := circuit.fetchAndApplyMicrodescriptors(ctx, cns, chunk, i); err != nil {
			return err
		}
	}

	log.Info().Msg("bootstrap complete")
	return nil
}

func (circuit *Circuit) fetchAndApplyMicrodescriptors(ctx context.Context, cons *common.Consensus, digestsSlice []string, offset int) error {
	desc, err := circuit.GetMicrodescriptors(digestsSlice)
	if err != nil {
		return fail(ctx, ErrDirectory, "fetch microdescriptors failed", err)
	}

	curve := ecdh.X25519()
	for i, v := range desc {
		if v == nil {
			continue
		}
		idx := offset + i
		if idx >= len(cons.RelayInformation) {
			logger(ctx).Error().Int("idx", idx).Int("len", len(cons.RelayInformation)).Msg("microdesc index out of bounds")
			return Public(ErrDirectory, "microdescriptor index out of bounds")
		}

		cons.RelayInformation[idx].OnionKey = v.OnionKey
		ntor, err := curve.NewPublicKey(v.NTorOnionKey)
		if err != nil {
			return fail(ctx, ErrDirectory, "invalid ntor onion key", err)
		}
		cons.RelayInformation[idx].NTorOnionKey = ntor
		if v.ExitRules != nil {
			cons.RelayInformation[idx].Ports = *v.ExitRules
		}
		cons.RelayInformation[idx].Family = v.Family
		cons.RelayInformation[idx].Familys = v.Familys
		cons.RelayInformation[idx].IdEd25519 = v.IdEd25519
	}

	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
