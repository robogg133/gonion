package gonion

import (
	"context"
	"crypto/ecdh"
	"math/rand"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

// StartConsensusRefresh schedules periodic consensus re-fetch on circuit.
// It runs until ctx is cancelled. Safe to call once after bootstrap.
func (circuit *Circuit) StartConsensusRefresh(ctx context.Context, cns *common.Consensus) {
	if cns == nil {
		return
	}
	go circuit.nextConsensus(ctx, cns)
}

// nextConsensus will refresh the consensus when needed (Tor client schedule).
func (circuit *Circuit) nextConsensus(ctx context.Context, cns *common.Consensus) {
	log := logger(ctx).With().Str("job", "consensus_refresh").Logger()

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("consensus refresh stopped")
			return
		default:
		}

		fetchTime, err := nextConsensusFetchTime(cns, time.Now().UTC())
		if err != nil {
			log.Error().Err(err).Msg("compute consensus fetch window failed")
			// Retry later instead of spinning.
			if err := sleepCtx(ctx, time.Hour); err != nil {
				return
			}
			continue
		}

		log.Info().Time("fetch_at", fetchTime).Msg("scheduled consensus refresh")

		if err := sleepCtx(ctx, time.Until(fetchTime)); err != nil {
			log.Debug().Err(err).Msg("consensus refresh cancelled")
			return
		}

		cnsPtr, err := circuit.GetConsensus(ConsensusFlavorMicrodesc)
		if err != nil {
			log.Error().Err(err).Msg("consensus refresh failed; retrying in 30m")
			if err := sleepCtx(ctx, 30*time.Minute); err != nil {
				return
			}
			continue
		}

		// Keep microdesc keys from previous consensus where digests match;
		// full re-bootstrap of microdescs is left to a higher-level client later.
		*cns = *cnsPtr
		common.SetGlobalConsensus(cns)
		if circuit.conn.storage != nil {
			if err := circuit.conn.storage.StoreConsensus(cns); err != nil {
				log.Warn().Err(err).Msg("store refreshed consensus failed")
			}
		}
		log.Info().Int("relays", len(cns.RelayInformation)).Msg("consensus refreshed")
	}
}

// NextConsensusFetchTimeForTest exposes nextConsensusFetchTime for unit tests.
func NextConsensusFetchTimeForTest(cns *common.Consensus, now time.Time) (time.Time, error) {
	return nextConsensusFetchTime(cns, now)
}

// nextConsensusFetchTime picks a random time in the Tor client download window:
// [FreshUntil + 3/4*(FreshUntil-ValidAfter), FreshUntil + 7/8*(ValidUntil-FreshUntil)].
func nextConsensusFetchTime(cns *common.Consensus, now time.Time) (time.Time, error) {
	if cns.FreshUntil.IsZero() || cns.ValidAfter.IsZero() || cns.ValidUntil.IsZero() {
		return time.Time{}, Public(ErrDirectory, "consensus timestamps missing")
	}

	freshWindow := cns.FreshUntil.Sub(cns.ValidAfter)
	if freshWindow <= 0 {
		freshWindow = time.Hour
	}
	validSpan := cns.ValidUntil.Sub(cns.FreshUntil)
	if validSpan <= 0 {
		validSpan = 2 * time.Hour
	}

	start := cns.FreshUntil.Add(freshWindow * 3 / 4)
	end := cns.FreshUntil.Add(validSpan * 7 / 8)

	if !end.After(start) {
		return time.Time{}, Public(ErrDirectory, "invalid consensus refresh window")
	}

	// If we are already past the window, schedule soon (jittered).
	if now.After(end) {
		return now.Add(time.Duration(rand.Int63n(int64(5 * time.Minute)))), nil
	}
	if now.After(start) {
		start = now
	}
	if !end.After(start) {
		return now.Add(time.Minute), nil
	}

	ns, ne := start.Unix(), end.Unix()
	span := ne - ns
	if span <= 0 {
		return start, nil
	}
	return time.Unix(ns+rand.Int63n(span), 0).UTC(), nil
}

// BootstrapOneConn fetches consensus and microdescriptors using one OR connection.
// On success it starts the consensus refresh scheduler on the bootstrap circuit.
func BootstrapOneConn(conn *Conn) error {
	ctx := conn.ctx
	log := logger(ctx).With().Str("job", "bootstrap").Logger()
	ctx = withLogger(ctx, log)
	log.Info().Msg("bootstrap starting")

	if conn.storage != nil {
		if cached, err := conn.storage.GetConsensus(); err == nil && cached != nil && cached.ValidUntil.After(time.Now().UTC()) {
			log.Info().Int("relays", len(cached.RelayInformation)).Time("valid_until", cached.ValidUntil).Msg("using cached consensus")
			common.SetGlobalConsensus(cached)
			return nil
		}
	}

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		return fail(ctx, ErrBootstrap, "create bootstrap circuit failed", err)
	}

	cns, err := circuit.GetConsensus(ConsensusFlavorMicrodesc)
	if err != nil {
		return fail(ctx, ErrBootstrap, "fetch consensus failed", err)
	}
	log.Info().Int("relays", len(cns.RelayInformation)).Msg("consensus fetched")

	if conn.storage != nil {
		if err := conn.storage.StoreConsensus(cns); err != nil {
			log.Warn().Err(err).Msg("store cached consensus failed")
		}
	}

	common.SetGlobalConsensus(cns)

	var allDigests []string
	for _, relay := range cns.RelayInformation {
		allDigests = append(allDigests, relay.MicrodescriptorDigest)
	}

	applied := 0
	for i := 0; i < len(allDigests); i += 91 {
		end := min(i+91, len(allDigests))
		chunk := allDigests[i:end]
		log.Debug().Int("offset", i).Int("count", len(chunk)).Msg("fetching microdescriptor chunk")
		n, err := circuit.fetchAndApplyMicrodescriptors(ctx, cns, chunk, i)
		if err != nil {
			return err
		}
		applied += n
	}

	withKeys := 0
	exitPort80 := 0
	for i := range cns.RelayInformation {
		r := &cns.RelayInformation[i]
		if r.NTorOnionKey != nil && len(r.IdEd25519) > 0 {
			withKeys++
		}
		if r.StatusFlags[common.FLAG_EXIT] && !r.StatusFlags[common.FLAG_BAD_EXIT] && r.Ports.IsAllowed(80) {
			exitPort80++
		}
	}
	log.Info().
		Int("relays", len(cns.RelayInformation)).
		Int("microdescs_applied", applied).
		Int("with_keys", withKeys).
		Int("exits_port_80", exitPort80).
		Msg("bootstrap complete")

	// Keep refreshing consensus until the connection is closed.
	circuit.StartConsensusRefresh(conn.ctx, cns)
	return nil
}

func (circuit *Circuit) fetchAndApplyMicrodescriptors(ctx context.Context, cons *common.Consensus, digestsSlice []string, offset int) (int, error) {
	desc, err := circuit.GetMicrodescriptors(digestsSlice)
	if err != nil {
		return 0, fail(ctx, ErrDirectory, "fetch microdescriptors failed", err)
	}

	curve := ecdh.X25519()
	applied := 0
	for i, v := range desc {
		if v == nil {
			continue
		}
		idx := offset + i
		if idx >= len(cons.RelayInformation) {
			logger(ctx).Error().Int("idx", idx).Int("len", len(cons.RelayInformation)).Msg("microdesc index out of bounds")
			return applied, Public(ErrDirectory, "microdescriptor index out of bounds")
		}

		cons.RelayInformation[idx].OnionKey = v.OnionKey
		if len(v.NTorOnionKey) > 0 {
			ntor, err := curve.NewPublicKey(v.NTorOnionKey)
			if err != nil {
				logger(ctx).Debug().Err(err).Int("idx", idx).Msg("skip invalid ntor key")
				continue
			}
			cons.RelayInformation[idx].NTorOnionKey = ntor
		}
		if v.ExitRules != nil {
			cons.RelayInformation[idx].Ports = *v.ExitRules
		}
		cons.RelayInformation[idx].Family = v.Family
		cons.RelayInformation[idx].Familys = v.Familys
		if len(v.IdEd25519) > 0 {
			cons.RelayInformation[idx].IdEd25519 = v.IdEd25519
		}
		applied++
	}

	return applied, nil
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
