package capi

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/path"
)

// PublicGuardProvider supplies the one synchronized manager shared by every
// public circuit purpose. A nil manager is an explicit fail-closed policy.
type PublicGuardProvider interface{ PublicGuardManager() *path.GuardManager }

// GuardConnectionFailure identifies only failure of the selected first-hop
// connection, before later extensions. Cancellation must never be wrapped.
type GuardConnectionFailure struct{ Err error }

func (e *GuardConnectionFailure) Error() string { return fmt.Sprintf("guard connection: %v", e.Err) }
func (e *GuardConnectionFailure) Unwrap() error { return e.Err }

// BuildGuardedCircuit is the shared exit/HS construction seam. A fixed pinned
// bridge bypasses public state. Public circuits cannot fall back to stateless
// guards, and are returned only after durable confirmation and usability. A
// non-counted purpose (path.BuildPurpose) keeps the full guard-lease lifecycle
// but persists no path-bias counters, matching C's pathbias_should_count.
func BuildGuardedCircuit(ctx context.Context, b CircuitBuilder, cns *common.Consensus, id uint32, hops uint, port uint16, tail *common.RouterStatus, stable bool, purpose ...path.BuildPurpose) (Circ, []*common.RouterStatus, error) {
	p := path.PurposeCounted
	if len(purpose) > 0 {
		p = purpose[0]
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if b == nil || hops < 2 {
		return nil, nil, fmt.Errorf("capi: multi-hop circuit builder is required")
	}
	fixed, err := CircuitGuard(ctx, b)
	if err != nil {
		return nil, nil, err
	}
	selector := path.NewWithGuard(cns, stable, fixed)
	target := common.CloneRouter(tail)
	if target == nil {
		target, err = selector.SelectTail(port)
		if err != nil {
			return nil, nil, err
		}
	}
	var lease *path.GuardLease
	if fixed == nil {
		provider, ok := b.(PublicGuardProvider)
		if !ok || provider.PublicGuardManager() == nil {
			return nil, nil, path.ErrGuardPersistence
		}
		lease, err = provider.PublicGuardManager().Select(ctx, cns, target)
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			if lease != nil {
				lease.Close()
			}
		}()
		selector = path.NewWithGuard(cns, stable, lease.Relay())
	}
	if err = selector.SelectCircuitTo(hops, target); err != nil {
		return nil, nil, err
	}
	relays := selector.Circuit()
	var circ Circ
	var buildErr error
	if cb, ok := b.(ContextCircuitBuilder); ok {
		buildCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		circ, err = cb.BuildPathContext(buildCtx, id, relays)
		buildErr = buildCtx.Err()
		if buildErr != nil {
			if circ != nil {
				_ = circ.Close()
				circ = nil
			}
			// Keep a per-hop progress error from the builder so a timed-out
			// build still reports how many hops had opened; the caller's own
			// deadline stays the timeout signal.
			var progress buildProgress
			if !errors.As(err, &progress) {
				err = buildErr
			}
		}
		cancel()
	} else {
		circ, err = b.BuildPath(id, relays)
	}
	if ctx.Err() != nil {
		if circ != nil {
			_ = circ.Close()
		}
		return nil, nil, ctx.Err()
	}
	if err != nil {
		if circ != nil {
			_ = circ.Close()
		}
		if lease != nil {
			var failure *GuardConnectionFailure
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && errors.As(err, &failure) {
				if saveErr := lease.Unreachable(); saveErr != nil {
					return nil, nil, saveErr
				}
			} else if p == path.PurposeCounted {
				// Construction path-bias accounting (path-spec §7.1) is skipped
				// for a purpose C's pathbias_should_count excludes; the guard
				// lease lifecycle above is unaffected.
				if buildErr != nil || errors.Is(err, context.DeadlineExceeded) {
					// The builder's fixed deadline is the right-censored
					// timeout (path-spec §7.1). Per-hop attribution: the attempt
					// is counted only once a second hop opened (a processed
					// CREATED/EXTENDED reply, C circuit_finish_handshake); a
					// timeout before that point is a guard connection failure,
					// not path bias.
					if hops := pathBiasHops(err); hops >= 2 {
						_ = lease.PathBiasBuildTimedOut()
					}
				} else if hops := pathBiasHops(err); hops >= 2 {
					// The build failed after committing to a second hop through
					// the guard; failures at the guard handshake itself never
					// reach this wrapper and do not count (path-spec §7.1).
					_ = lease.PathBiasBuildAttempted()
				}
			}
		}
		return nil, nil, err
	}
	if circ == nil {
		return nil, nil, fmt.Errorf("capi: builder returned nil circuit")
	}
	if err = circ.Ctx().Err(); err != nil {
		_ = circ.Close()
		return nil, nil, err
	}
	if lease != nil {
		if p == path.PurposeCounted {
			// A completed multi-hop build is one construction attempt and one
			// construction success through this guard (path-spec §7.1). A
			// non-counted purpose persists no counter but keeps its lifecycle.
			if err = lease.PathBiasBuildSucceeded(); err != nil {
				_ = circ.Close()
				return nil, nil, err
			}
		}
		wrapped := &guardLeaseCircuit{Circ: circ, lease: lease, countBias: p == path.PurposeCounted}
		lease = nil
		// A circuit that dies before the client closes it is still accounted,
		// without any reachability inference (path-spec §7.2).
		context.AfterFunc(circ.Ctx(), func() { wrapped.accountClosed(false) })
		waitCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(circ.Ctx(), cancel)
		if err = wrapped.lease.Succeeded(waitCtx); err == nil {
			err = wrapped.lease.Wait(waitCtx)
		}
		stop()
		cancel()
		if err == nil {
			if ended := circ.Ctx().Err(); ended != nil {
				err = ended
			}
			if ended := ctx.Err(); ended != nil {
				err = ended
			}
		}
		if err != nil {
			_ = wrapped.Close()
			return nil, nil, err
		}
		if service, ok := circ.(ServiceCirc); ok {
			return &guardLeaseServiceCircuit{guardLeaseCircuit: wrapped, service: service}, relays, nil
		}
		return wrapped, relays, nil
	}
	return circ, relays, nil
}

type guardLeaseCircuit struct {
	Circ
	lease *path.GuardLease
	once  sync.Once
	err   error
	// Path-bias usage state (path-spec §7.2): the attempt is counted once per
	// circuit and the success stays provisional until close.
	accounted sync.Once
	mu        sync.Mutex
	use       uint8 // useNone, useAttempted, useSucceeded
	// countBias gates every path-bias counter mutation for a purpose C's
	// pathbias_should_count excludes. The wrapper keeps its full lifecycle
	// (Close, natural-death hook, lease release) but persists no counter.
	countBias     bool
	accountedDone bool // set inside accountClosed; guards post-close misuse
}

const (
	useNone uint8 = iota
	useAttempted
	useSucceeded
)

// buildProgress is the optional hop-progress signal a builder error can carry
// for path-bias construction accounting: how many hops had opened when the
// build failed. The concrete *gonion.Conn provides it for its extension loop.
type buildProgress interface{ PathBiasHops() int }

// pathBiasHops reports how many hops were open when a multi-hop build failed,
// or zero when the error carries no per-hop progress (a guard-connection
// failure). Construction accounting credits an attempt only at two or more
// hops, the processed CREATED/EXTENDED reply that opened the second hop.
func pathBiasHops(err error) int {
	var progress buildProgress
	if errors.As(err, &progress) {
		return progress.PathBiasHops()
	}
	return 0
}

// NewStream is the stream attachment point (path-spec §7.2 usage attempt):
// the first attachment counts the attempt, a successful CONNECTED reply marks
// the provisional success, and any failed later attachment clears it again.
func (c *guardLeaseCircuit) NewStream(target string, hopDest int) (Stream, error) {
	c.beginUseAttempt()
	stream, err := c.Circ.NewStream(target, hopDest)
	if err != nil {
		c.clearUseSuccess()
		return nil, err
	}
	c.markUseRecognized()
	return stream, nil
}

// RecvHSControl recognizes the expected HS control cell for the circuit
// purpose (RENDEZVOUS2, INTRODUCE_ACK, INTRO_ESTABLISHED, INTRODUCE2) as
// usage activity, matching C's pathbias_mark_use_success call sites.
func (c *guardLeaseCircuit) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	cell, err := c.Circ.RecvHSControl(ctx)
	if err == nil {
		c.markUseRecognized()
	}
	return cell, err
}

// beginUseAttempt counts the single usage attempt of this circuit; later
// attachments and rollbacks never repeat it.
func (c *guardLeaseCircuit) beginUseAttempt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The circuit may outlive the accounted close only through caller
	// misuse; a post-close attach must not inject a counter event.
	if c.use == useNone && !c.accountedDone {
		c.use = useAttempted
		if c.countBias {
			_ = c.lease.PathBiasUseAttempted()
		}
	}
}

// markUseRecognized flags expected relay activity; the counter persists at
// close. An activity signal without a prior attachment counts the attempt,
// as C's pathbias_mark_use_success does for a strange start state.
func (c *guardLeaseCircuit) markUseRecognized() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.use == useSucceeded || c.accountedDone {
		return
	}
	if c.use == useNone {
		c.use = useAttempted
		if c.countBias {
			_ = c.lease.PathBiasUseAttempted()
		}
	}
	c.use = useSucceeded
}

// clearUseSuccess rolls a provisional success back to a bare attempt when a
// later attachment fails, so only the attempt remains until the close probe.
func (c *guardLeaseCircuit) clearUseSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.use == useSucceeded {
		c.use = useAttempted
	}
}

// accountClosed records the terminal close classification exactly once,
// whether the client closed the circuit or the circuit died first.
func (c *guardLeaseCircuit) accountClosed(byClient bool) {
	c.accounted.Do(func() {
		c.mu.Lock()
		c.accountedDone = true
		use := c.use
		count := c.countBias
		c.mu.Unlock()
		if !count {
			// A purpose C's pathbias_should_count excludes persists no close
			// counter; the accounted-once bookkeeping still runs.
			return
		}
		kind := path.PathBiasClientClose
		if !byClient {
			kind = path.PathBiasPrematureClose
		}
		switch use {
		case useSucceeded:
			kind = path.PathBiasUseSuccess
		case useAttempted:
			kind = path.PathBiasUseFailed
		}
		_ = c.lease.PathBiasCircuitClosed(kind)
	})
}

func (c *guardLeaseCircuit) Close() error {
	c.once.Do(func() {
		c.accountClosed(true)
		c.lease.Close()
		c.err = c.Circ.Close()
	})
	return c.err
}

type guardLeaseServiceCircuit struct {
	*guardLeaseCircuit
	service ServiceCirc
}

func (c *guardLeaseServiceCircuit) EstablishIntro(auth ed25519.PrivateKey) error {
	return c.service.EstablishIntro(auth)
}
func (c *guardLeaseServiceCircuit) JoinRendezvous(cookie [20]byte, reply, Kf, Kb, Df, Db []byte, address string) error {
	return c.service.JoinRendezvous(cookie, reply, Kf, Kb, Df, Db, address)
}
func (c *guardLeaseServiceCircuit) AcceptStream(ctx context.Context) (net.Conn, error) {
	return c.service.AcceptStream(ctx)
}
func (c *guardLeaseServiceCircuit) StopAccepting() error { return c.service.StopAccepting() }
