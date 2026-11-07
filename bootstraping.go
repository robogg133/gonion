package gonion

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"math/big"
	"net"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers/microdesc"
)

// StartConsensusRefresh preserves the low-level API without retaining the
// supplied circuit: later fetches create fresh one-hop directory circuits.
// Without an explicit redial policy a dead channel fails closed.
func (circuit *Circuit) StartConsensusRefresh(ctx context.Context, cns *common.Consensus) {
	if cns == nil || !cns.TrustedHydrated() || ctx.Err() != nil {
		return
	}
	_ = circuit.conn.startConsensusRecovery(ctx, nil, circuit.conn.relayRSA, nil)
}

// StartConsensusRecovery starts one connection-owned refresh worker. A nil dial
// permits fresh circuits on the original live channel only; a dead channel then
// fails closed. The caller supplies an explicit bootstrap/bridge redial policy.
// guard, when non-nil, must return the currently authenticated first-hop ntor
// descriptor; it is never replaced by a public relay or CREATE_FAST.
func (conn *Conn) StartConsensusRecovery(dial func(context.Context) (net.Conn, error), identity [20]byte, guard func(context.Context) (*common.RouterStatus, error)) error {
	return conn.startConsensusRecovery(context.Background(), dial, identity, guard)
}

func (conn *Conn) startConsensusRecovery(parent context.Context, dial func(context.Context) (net.Conn, error), identity [20]byte, guard func(context.Context) (*common.RouterStatus, error)) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if identity == [20]byte{} || conn.CheckRelayFingerprint(identity) != nil {
		return Public(ErrHandshake, "recovery requires the pinned bootstrap identity")
	}
	cns := conn.Consensus()
	if cns == nil || !cns.TrustedHydrated() || !cns.IsLive(time.Now()) {
		return Public(ErrDirectory, "recovery requires an authenticated live consensus")
	}
	conn.recoveryMu.Lock()
	defer conn.recoveryMu.Unlock()
	if conn.recoveryCancel != nil || conn.ctx.Err() != nil {
		return Public(ErrClosed, "directory recovery already started or connection closed")
	}
	ctx, cancel := context.WithCancel(parent)
	conn.recoveryCancel = cancel
	go conn.recoveryLoop(ctx, cns, dial, identity, guard)
	return nil
}

func (conn *Conn) recoveryLoop(ctx context.Context, previous *common.Consensus, dial func(context.Context) (net.Conn, error), identity [20]byte, guard func(context.Context) (*common.RouterStatus, error)) {
	defer func() {
		conn.recoveryMu.Lock()
		replacement := conn.recoveryConn
		conn.recoveryConn = nil
		conn.recoveryMu.Unlock()
		if replacement != nil {
			_ = replacement.Close()
		}
	}()
	for ctx.Err() == nil {
		at, err := nextConsensusFetchTime(previous, time.Now().UTC())
		if err != nil || sleepCtx(ctx, time.Until(at)) != nil {
			return
		}
		candidate, err := conn.refreshOnce(ctx, previous, dial, identity, guard)
		if err != nil {
			logger(ctx).Warn().Err(err).Msg("consensus recovery failed; retaining previous snapshot")
			if sleepCtx(ctx, 30*time.Minute) != nil {
				return
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		conn.publishVerifiedConsensus(ctx, candidate)
		previous = candidate
	}
}

// refreshOnce serializes recovery on one owned channel. On channel loss it
// redials only the caller's policy and verifies both pinned CERTS identities.
func (conn *Conn) refreshOnce(ctx context.Context, previous *common.Consensus, dial func(context.Context) (net.Conn, error), identity [20]byte, guard func(context.Context) (*common.RouterStatus, error)) (*common.Consensus, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for attempts := 0; attempts < 2; attempts++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn.recoveryMu.Lock()
		source := conn.recoveryConn
		conn.recoveryMu.Unlock()
		if source == nil {
			source = conn
		}
		if source.Context().Err() == nil {
			// Circuit constructors use the link context, not the fetch context.
			// Closing its socket also interrupts blocked CREATE/CREATED waits.
			stop := context.AfterFunc(ctx, func() { _ = source.socket.Close() })
			defer stop()
		}
		if source.Context().Err() != nil {
			var stop func()
			var err error
			pins := conn.trustedAuthorities
			source, stop, err = conn.reconnect(ctx, dial, identity, guard, func(raw net.Conn) (*Conn, error) {
				nc, oerr := NewConn(raw, nil, false)
				if oerr != nil {
					return nil, oerr
				}
				// Pins are set once before recovery starts, never mutated.
				nc.trustedAuthorities = pins
				return nc, nil
			})
			if err != nil {
				return nil, err
			}
			defer stop() // Cover circuit creation and hydration as well as handshake.
		}
		var relay *common.RouterStatus
		if guard != nil {
			var err error
			relay, err = guard(ctx)
			if err != nil {
				return nil, err
			}
			if err = source.CheckRelayIdentity(relay); err != nil {
				return nil, err
			}
		}
		var circuit *Circuit
		var err error
		if relay == nil {
			circuit, err = source.NewFastCircuit(1)
		} else {
			circuit, err = source.NewCircuitTo(1, relay)
		}
		if err == nil {
			candidate, fetchErr := circuit.getConsensus(ctx, ConsensusFlavorMicrodesc)
			if fetchErr == nil && !candidate.ValidAfter.After(previous.ValidAfter) {
				fetchErr = Public(ErrDirectory, "downloaded consensus is not newer")
			}
			if fetchErr == nil {
				candidate, fetchErr = hydrateConsensus(ctx, candidate, previous, func(d []string) ([]*common.Microdesc, error) { return circuit.getMicrodescriptors(ctx, d) })
			}
			_ = circuit.Close()
			if fetchErr == nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return candidate, nil
			}
			err = fetchErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if source.Context().Err() == nil || dial == nil {
			return nil, err
		}
	}
	return nil, Public(ErrDirectory, "directory channel recovery failed")
}

// reconnect keeps the link's cancellation hook alive until the caller has
// finished its directory attempt. open is internal so tests can simulate a
// peer handshake while the production path always uses NewConn/CERTS.
func (conn *Conn) reconnect(ctx context.Context, dial func(context.Context) (net.Conn, error), identity [20]byte, guard func(context.Context) (*common.RouterStatus, error), open func(net.Conn) (*Conn, error)) (*Conn, func(), error) {
	if dial == nil {
		return nil, nil, Public(ErrDirectory, "bootstrap channel lost without redial policy")
	}
	raw, err := dial(ctx)
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	if raw == nil {
		return nil, nil, Public(ErrIO, "bootstrap dialer returned nil connection")
	}
	if pinned, ok := raw.(interface{ ExpectedRelayIdentity() [20]byte }); ok && pinned.ExpectedRelayIdentity() != identity {
		_ = raw.Close()
		return nil, nil, Public(ErrHandshake, "bootstrap dialer identity pin changed")
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	next, err := open(raw)
	if err == nil && next == nil {
		err = Public(ErrIO, "bootstrap handshake returned nil connection")
	}
	if err == nil {
		err = next.CheckRelayFingerprint(identity)
	}
	if err == nil && next.relayEd != conn.relayEd {
		err = Public(ErrHandshake, "bootstrap Ed25519 identity changed on recovery")
	}
	if err == nil && guard != nil {
		var relay *common.RouterStatus
		relay, err = guard(ctx)
		if err == nil {
			err = next.CheckRelayIdentity(relay)
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		stop()
		if next != nil {
			_ = next.Close()
		} else {
			_ = raw.Close()
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	conn.recoveryMu.Lock()
	if ctx.Err() != nil {
		conn.recoveryMu.Unlock()
		stop()
		_ = next.Close()
		return nil, nil, ctx.Err()
	}
	old := conn.recoveryConn
	conn.recoveryConn = next
	conn.recoveryMu.Unlock()
	if old != nil {
		_ = old.Close()
	} else if conn.ctx.Err() != nil {
		// A failed link need not have gone through Conn.Close.
		_ = conn.socket.Close()
	}
	return next, func() { stop() }, nil
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
	return bootstrapOneConn(conn, nil, true)
}

// BootstrapOneConnManaged bootstraps without starting the legacy circuit-owned
// refresh worker. The owner must call StartConsensusRecovery after initialization.
func BootstrapOneConnManaged(conn *Conn, guard *common.RouterStatus) error {
	return bootstrapOneConn(conn, guard, false)
}

// BootstrapOneConnTo uses ntor when a pinned first-hop descriptor is already
// available, as with a bridge. It does not choose or dial another relay.
func BootstrapOneConnTo(conn *Conn, guard *common.RouterStatus) error {
	if guard == nil {
		return Public(ErrBootstrap, "missing bootstrap guard")
	}
	return bootstrapOneConn(conn, guard, true)
}

func bootstrapOneConn(conn *Conn, guard *common.RouterStatus, legacyRefresh bool) error {
	ctx := conn.ctx
	var cached *common.Consensus
	if conn.storage != nil {
		var err error
		cached, err = conn.storage.GetConsensus()
		if err != nil {
			logger(ctx).Debug().Err(err).Msg("consensus cache unavailable")
		}
	}
	var circuit *Circuit
	var err error
	if guard == nil {
		circuit, err = conn.NewFastCircuit(1)
	} else {
		circuit, err = conn.NewCircuitTo(1, guard)
	}
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
	if legacyRefresh {
		if guard == nil {
			circuit.StartConsensusRefresh(ctx, candidate)
		} else {
			fixed := common.CloneRouter(guard)
			_ = conn.startConsensusRecovery(ctx, nil, conn.relayRSA, func(context.Context) (*common.RouterStatus, error) { return common.CloneRouter(fixed), nil })
		}
	}
	_ = circuit.Close()
	success = true
	return nil
}

func (circuit *Circuit) publishConsensus(ctx context.Context, c *common.Consensus) {
	if !c.IsAuthenticated() || !c.IsLive(time.Now().UTC()) || !c.TrustedHydrated() {
		logger(ctx).Error().Msg("refusing to publish unverified or incomplete consensus")
		return
	}
	circuit.conn.publishVerifiedConsensus(ctx, c)
}

func (conn *Conn) publishVerifiedConsensus(ctx context.Context, c *common.Consensus) {
	conn.publishMu.Lock()
	defer conn.publishMu.Unlock()
	if !c.IsAuthenticated() || !c.IsLive(time.Now().UTC()) || !c.TrustedHydrated() {
		logger(ctx).Error().Msg("refusing to publish unverified or incomplete consensus")
		return
	}
	c = c.Trusted()
	conn.mu.RLock()
	previous := conn.consensus
	if previous != nil && (c.ValidAfter.Before(previous.ValidAfter) ||
		(c.ValidAfter.Equal(previous.ValidAfter) && !bytes.Equal(c.RawDocument, previous.RawDocument))) {
		conn.mu.RUnlock()
		logger(ctx).Warn().Msg("refusing older or conflicting consensus epoch")
		return
	}
	conn.mu.RUnlock()
	if conn.storage != nil {
		if err := conn.storage.StoreConsensus(c.Clone()); err != nil {
			logger(ctx).Warn().Err(err).Msg("store hydrated consensus failed")
		}
	}
	conn.mu.Lock()
	conn.consensus = c.Trusted()
	conn.mu.Unlock()
	common.SetGlobalConsensus(c.Trusted())
	logger(ctx).Info().Int("relays", len(c.RelayInformation)).Msg("authenticated hydrated consensus published")
}

// Hydration is all-or-nothing. Cached descriptor bytes must match a digest in
// the current consensus; cached flags, addresses, keys and booleans are ignored.
func hydrateConsensus(ctx context.Context, candidate, previous *common.Consensus, fetch func([]string) ([]*common.Microdesc, error)) (*common.Consensus, error) {
	if candidate == nil || !candidate.IsAuthenticated() || !candidate.IsLive(time.Now().UTC()) {
		return nil, Public(ErrDirectory, "authenticated live consensus required for hydration")
	}
	candidate = candidate.Trusted()
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	if candidate.Flavor != ConsensusFlavorMicrodesc {
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
	if len(out.RelayInformation) == 0 || !out.IsLive(time.Now().UTC()) {
		return nil, Public(ErrDirectory, "consensus is empty, incomplete, or expired during hydration")
	}
	return candidate.OwnAuthenticatedHydration(out.Microdescriptors)
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
