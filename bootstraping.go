package gonion

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"math/big"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers/microdesc"
)

// StartConsensusRefresh schedules refreshes until ctx or the circuit is closed.
// Call once per bootstrap circuit. The supplied snapshot is never modified.
func (circuit *Circuit) StartConsensusRefresh(ctx context.Context, cns *common.Consensus) {
	if cns == nil {
		return
	}
	go circuit.nextConsensus(ctx, cns.Clone())
}

func (circuit *Circuit) nextConsensus(parent context.Context, cns *common.Consensus) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(circuit.Ctx, cancel)
	defer stop()
	log := logger(ctx).With().Str("job", "consensus_refresh").Logger()
	for ctx.Err() == nil {
		fetchTime, err := nextConsensusFetchTime(cns, time.Now().UTC())
		if err != nil {
			log.Error().Err(err).Msg("invalid consensus refresh window")
			return
		}
		if sleepCtx(ctx, time.Until(fetchTime)) != nil {
			return
		}
		candidate, err := circuit.getConsensus(ctx, ConsensusFlavorMicrodesc)
		if err == nil && !candidate.ValidAfter.After(cns.ValidAfter) {
			err = Public(ErrDirectory, "downloaded consensus is not newer")
		}
		if err == nil {
			candidate, err = hydrateConsensus(ctx, candidate, cns, func(d []string) ([]*common.Microdesc, error) { return circuit.getMicrodescriptors(ctx, d) })
		}
		if err != nil {
			log.Warn().Err(err).Msg("consensus refresh failed; retaining previous snapshot and retrying in 30m")
			if sleepCtx(ctx, 30*time.Minute) != nil {
				return
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		circuit.publishConsensus(ctx, candidate)
		cns = candidate
	}
}

func NextConsensusFetchTimeForTest(cns *common.Consensus, now time.Time) (time.Time, error) {
	return nextConsensusFetchTime(cns, now)
}

// dir-spec 5.1: start = FU + 3/4*(FU-VA), end = start + 7/8*(VU-start).
func nextConsensusFetchTime(cns *common.Consensus, now time.Time) (time.Time, error) {
	if cns == nil || cns.ValidAfter.IsZero() || !cns.FreshUntil.After(cns.ValidAfter) || !cns.ValidUntil.After(cns.FreshUntil) {
		return time.Time{}, Public(ErrDirectory, "invalid consensus timestamps")
	}
	start := cns.FreshUntil.Add(cns.FreshUntil.Sub(cns.ValidAfter) / 4 * 3)
	if !start.Before(cns.ValidUntil) {
		return time.Time{}, Public(ErrDirectory, "invalid consensus refresh window")
	}
	end := start.Add(cns.ValidUntil.Sub(start) / 8 * 7)
	if !now.Before(end) {
		return now, nil
	}
	if now.After(start) {
		start = now
	}
	span := end.Sub(start)
	if span <= 0 {
		return start, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return time.Time{}, err
	}
	return start.Add(time.Duration(n.Int64())), nil
}

// BootstrapOneConn hydrates a private candidate before publishing or persisting.
// Cached documents are reauthenticated; cache hits also start refresh.
func BootstrapOneConn(conn *Conn) error {
	ctx := conn.ctx
	var cached *common.Consensus
	if conn.storage != nil {
		var err error
		cached, err = conn.storage.GetConsensus()
		if err != nil {
			logger(ctx).Debug().Err(err).Msg("consensus cache unavailable")
		}
	}
	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		return fail(ctx, ErrBootstrap, "create bootstrap circuit failed", err)
	}
	success := false
	defer func() {
		if !success {
			_ = circuit.Close()
		}
	}()
	var candidate *common.Consensus
	if cached != nil && cached.Flavor == ConsensusFlavorMicrodesc {
		candidate, err = circuit.authenticateConsensus(ctx, cached)
	}
	if candidate == nil {
		candidate, err = circuit.getConsensus(ctx, ConsensusFlavorMicrodesc)
		if err != nil {
			return fail(ctx, ErrBootstrap, "fetch consensus failed", err)
		}
	}
	candidate, err = hydrateConsensus(ctx, candidate, cached, func(d []string) ([]*common.Microdesc, error) { return circuit.getMicrodescriptors(ctx, d) })
	if err != nil {
		return fail(ctx, ErrBootstrap, "hydrate consensus failed", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	circuit.publishConsensus(ctx, candidate)
	circuit.StartConsensusRefresh(ctx, candidate)
	success = true
	return nil
}

func (circuit *Circuit) publishConsensus(ctx context.Context, c *common.Consensus) {
	if !c.IsAuthenticated() || !c.IsLive(time.Now().UTC()) || !c.IsHydrated() {
		logger(ctx).Error().Msg("refusing to publish unverified or incomplete consensus")
		return
	}
	if circuit.conn.storage != nil {
		if err := circuit.conn.storage.StoreConsensus(c); err != nil {
			logger(ctx).Warn().Err(err).Msg("store hydrated consensus failed")
		}
	}
	circuit.conn.mu.Lock()
	circuit.conn.consensus = c.Clone()
	circuit.conn.mu.Unlock()
	common.SetGlobalConsensus(c)
	logger(ctx).Info().Int("relays", len(c.RelayInformation)).Msg("authenticated hydrated consensus published")
}

// Hydration is all-or-nothing. Cached descriptor bytes must match a digest in
// the current consensus; cached flags, addresses, keys and booleans are ignored.
func hydrateConsensus(ctx context.Context, candidate, previous *common.Consensus, fetch func([]string) ([]*common.Microdesc, error)) (*common.Consensus, error) {
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	if candidate.Flavor != ConsensusFlavorMicrodesc || !candidate.IsLive(time.Now().UTC()) {
		return nil, Public(ErrDirectory, "expected a live microdesc consensus")
	}
	out := candidate.Clone()
	old := previous.Clone()
	out.Microdescriptors = make(map[string][]byte)
	var missing []string
	indices := make(map[string][]int)
	for i := range out.RelayInformation {
		r := &out.RelayInformation[i]
		// Never trust the presence of a key alone as evidence of hydration.
		r.OnionKey, r.NTorOnionKey, r.IdEd25519, r.Family, r.Familys = nil, nil, nil, nil, nil
		r.Ports, r.MicrodescriptorLoaded = common.Ports{}, false

		if _, found := indices[r.MicrodescriptorDigest]; !found {
			missing = append(missing, r.MicrodescriptorDigest)
		}
		indices[r.MicrodescriptorDigest] = append(indices[r.MicrodescriptorDigest], i)
	}
	for offset := 0; offset < len(missing); offset += 91 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		digests := missing[offset:min(offset+91, len(missing))]
		descriptors := make([]*common.Microdesc, len(digests))
		var need []string
		for i, digest := range digests {
			if old != nil {
				if raw := old.Microdescriptors[digest]; len(raw) > 0 {
					parsed, err := (microdesc.Parser{}).Parse(bytes.NewReader(raw), []string{digest})
					if err == nil {
						descriptors[i] = parsed[0]
					}
				}
			}
			if descriptors[i] == nil {
				need = append(need, digest)
			}
		}
		if len(need) != 0 {
			fetched, err := fetch(need)
			if err != nil {
				return nil, err
			}
			if len(fetched) != len(need) {
				return nil, Public(ErrDirectory, "microdescriptor response count mismatch")
			}
			j := 0
			for i := range descriptors {
				if descriptors[i] == nil {
					descriptors[i] = fetched[j]
					j++
				}
			}
		}
		for i, md := range descriptors {
			if md == nil {
				return nil, Publicf(ErrDirectory, "missing microdescriptor %s", digests[i])
			}
			// A parsed cached model is not evidence: authenticate its original bytes.
			checked, err := (microdesc.Parser{}).Parse(bytes.NewReader(md.RawDocument), []string{digests[i]})
			if err != nil || checked[0] == nil {
				return nil, Public(ErrDirectory, "microdescriptor digest verification failed")
			}
			md = checked[0]
			out.Microdescriptors[digests[i]] = bytes.Clone(md.RawDocument)
			key, err := ecdh.X25519().NewPublicKey(md.NTorOnionKey)
			if err != nil || (len(md.IdEd25519) != 0 && len(md.IdEd25519) != 32) {
				return nil, Public(ErrDirectory, "invalid microdescriptor key")
			}
			for _, index := range indices[digests[i]] {
				r := &out.RelayInformation[index]
				r.OnionKey, r.NTorOnionKey, r.IdEd25519 = md.OnionKey, key, md.IdEd25519
				r.Family, r.Familys = md.Family, md.Familys
				if md.ExitRules != nil {
					r.Ports = *md.ExitRules
				}
				if r.StatusFlags[common.FLAG_NO_ED_CONSENSUS] {
					r.IdEd25519 = nil
				}
				r.MicrodescriptorLoaded = true
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !out.IsHydrated() || !out.IsLive(time.Now().UTC()) {
		return nil, Public(ErrDirectory, "consensus is empty, incomplete, or expired during hydration")
	}
	return out.Clone(), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
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
