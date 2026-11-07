package path

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

var ErrGuardPersistence = errors.New("path: durable public guard persistence is required")
var ErrGuardPathBias = errors.New("path: path-bias enforcement is not implemented")

// GuardPersistence is separate from the directory cache. Load returns nil only
// for a genuinely absent first-run state. Save must atomically replace and
// durably commit the entire snapshot before returning success. Callbacks must
// honor ctx, must not reenter the manager, and must not share this state with
// another manager/process without external exclusive ownership. A failed Save
// poisons the manager: reconstruct it from durable storage to recover.
type GuardPersistence struct {
	Load func(context.Context) ([]byte, error)
	Save func(context.Context, []byte) error
}

// GuardSnapshot is a versioned public-default state. Slice order is sample
// order; ConfirmedIndex is one-based, zero means unconfirmed. Unknown JSON
// fields are rejected rather than silently discarded. Reachability, pending,
// primaries and relay descriptors are deliberately not durable.
type GuardSnapshot struct {
	Version        int           `json:"version"`
	Instance       string        `json:"instance"`
	LastValidAfter time.Time     `json:"last_valid_after"`
	Guards         []GuardRecord `json:"guards"`
}
type GuardRecord struct {
	Identity       [20]byte      `json:"identity"`
	SampledOn      time.Time     `json:"sampled_on"`
	SampledBy      string        `json:"sampled_by"`
	Listed         bool          `json:"listed"`
	UnlistedSince  time.Time     `json:"unlisted_since"`
	ConfirmedOn    time.Time     `json:"confirmed_on"`
	ConfirmedIndex uint64        `json:"confirmed_index"`
	PathBias       GuardPathBias `json:"path_bias"`
}

// GuardPathBias retains existing counters across restarts. Accounting and probes
// are an outstanding release gate; these values are never inferred from generic
// builder/stream errors or used to pretend enforcement is available.
type GuardPathBias struct {
	UseAttempts              float64 `json:"use_attempts"`
	UseSuccesses             float64 `json:"use_successes"`
	CircAttempts             float64 `json:"circ_attempts"`
	CircSuccesses            float64 `json:"circ_successes"`
	SuccessfulCircuitsClosed float64 `json:"successful_circuits_closed"`
	CollapsedCircuits        float64 `json:"collapsed_circuits"`
	UnusableCircuits         float64 `json:"unusable_circuits"`
	Timeouts                 float64 `json:"timeouts"`
	Disabled                 bool    `json:"disabled"`
}

type guardRuntime struct {
	reachable                                      int // 0 maybe, 1 yes, -1 no
	pending                                        bool
	pendingAttempts                                int
	pendingGeneration                              uint64
	pendingSince, lastTried, failingSince, retryAt time.Time
	delay                                          time.Duration
}

// PathBiasClose is the terminal close classification of a guarded circuit
// whose build completed, per path-spec §7 and C's pathbias_check_close. The
// collapsed/unusable/timeouts counters are informational: the measured
// construction rate is circ_successes over circ_attempts.
type PathBiasClose uint8

const (
	// PathBiasClientClose: the client closed a built circuit that carried no
	// usage attempt; counted as a successfully closed circuit.
	PathBiasClientClose PathBiasClose = iota
	// PathBiasPrematureClose: the circuit died before the client closed it and
	// saw no recognized usage; counted as a collapsed circuit.
	PathBiasPrematureClose
	// PathBiasUseSuccess: the circuit closed after expected relay activity was
	// observed; the usage success is finalized and the close counted.
	PathBiasUseSuccess
	// PathBiasUseFailed: the circuit closed while its last state was a bare
	// usage attempt without recognized activity. The §7.2 close-time probe is
	// not available through the circuit API, so it is counted directly.
	// shortcut: skips the END-cell nonce echo that would distinguish a real
	// usage failure from an already-served circuit, which errs toward more
	// unusable_circuits; upgrade when relay END payload parsing exists.
	PathBiasUseFailed
)

// GuardManager implements the unrestricted public-default guard state. Pinned
// bridges do not use this manager. Path-bias probes/accounting are not supplied
// by the current circuit API; enforcement requests fail explicitly.
type GuardManager struct {
	mu           sync.Mutex
	persistence  GuardPersistence
	state        GuardSnapshot
	runtime      map[[20]byte]*guardRuntime
	primary      [][20]byte
	directory    *Selector
	failure      error
	lastInternet time.Time
	now          func() time.Time
}

func NewGuardManager(ctx context.Context, p GuardPersistence) (*GuardManager, error) {
	if p.Load == nil || p.Save == nil {
		return nil, ErrGuardPersistence
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := p.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("path: load guards: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := &GuardManager{persistence: p, state: GuardSnapshot{Version: 1, Instance: "public-default"}, runtime: make(map[[20]byte]*guardRuntime), now: time.Now}
	if data != nil {
		if err := decodeGuards(data, &m.state, m.now()); err != nil {
			return nil, err
		}
	}
	for _, g := range m.state.Guards {
		m.runtime[g.Identity] = &guardRuntime{}
	}
	return m, nil
}

func decodeGuards(data []byte, state *GuardSnapshot, now time.Time) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return fmt.Errorf("path: invalid guard snapshot length")
	}
	if err := rejectDuplicateGuardFields(data); err != nil {
		return err
	}
	// Reject unknown fields rather than losing future guard history.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("path: invalid guard snapshot: %w", err)
	}
	for k := range fields {
		if k != "version" && k != "instance" && k != "guards" && k != "last_valid_after" {
			return fmt.Errorf("path: unknown guard snapshot field %q", k)
		}
	}
	for _, key := range []string{"version", "instance", "guards"} {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("path: missing guard snapshot field %q", key)
		}
	}
	// Struct decoding matches names case-insensitively and pads or truncates
	// fixed arrays. Validate the persisted security identity before decoding.
	var records []json.RawMessage
	if err := json.Unmarshal(fields["guards"], &records); err != nil || records == nil {
		return fmt.Errorf("path: invalid guard records")
	}
	if len(records) > 60 {
		return fmt.Errorf("path: too many guard records")
	}
	for _, raw := range records {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(raw, &record); err != nil || record == nil {
			return fmt.Errorf("path: invalid guard record")
		}
		for key := range record {
			switch key {
			case "identity", "sampled_on", "sampled_by", "listed", "unlisted_since", "confirmed_on", "confirmed_index", "path_bias":
			default:
				return fmt.Errorf("path: unknown guard record field %q", key)
			}
		}
		var identity []json.RawMessage
		if err := json.Unmarshal(record["identity"], &identity); err != nil || len(identity) != 20 {
			return fmt.Errorf("path: invalid guard identity length or type")
		}
		for _, element := range identity {
			var value uint8
			if err := json.Unmarshal(element, &value); err != nil || len(element) == 0 || element[0] < '0' || element[0] > '9' {
				return fmt.Errorf("path: invalid guard identity byte")
			}
		}
		if bias, ok := record["path_bias"]; ok {
			var counters map[string]json.RawMessage
			if err := json.Unmarshal(bias, &counters); err != nil || counters == nil {
				return fmt.Errorf("path: invalid guard path-bias state")
			}
			for key := range counters {
				switch key {
				case "use_attempts", "use_successes", "circ_attempts", "circ_successes", "successful_circuits_closed", "collapsed_circuits", "unusable_circuits", "timeouts", "disabled":
				default:
					return fmt.Errorf("path: unknown path-bias field %q", key)
				}
			}
		}
	}
	*state = GuardSnapshot{}
	// DisallowUnknownFields also checks nested records.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(state); err != nil {
		return fmt.Errorf("path: invalid guard snapshot: %w", err)
	}
	if state.Version != 1 || state.Instance != "public-default" || len(state.Guards) > 60 || state.LastValidAfter.After(now) {
		return fmt.Errorf("path: unsupported guard snapshot")
	}
	seen := make(map[[20]byte]bool)
	indices := make(map[uint64]bool)
	for _, g := range state.Guards {
		if g.Identity == [20]byte{} || seen[g.Identity] || g.SampledOn.IsZero() || g.SampledOn.After(now) || g.SampledOn.Year() < 1970 || g.SampledBy == "" || len(g.SampledBy) > 128 {
			return fmt.Errorf("path: invalid sampled guard")
		}
		seen[g.Identity] = true
		if g.Listed != g.UnlistedSince.IsZero() || g.UnlistedSince.After(now) || (!g.UnlistedSince.IsZero() && g.UnlistedSince.Year() < 1970) {
			return fmt.Errorf("path: invalid guard listing time")
		}
		if (g.ConfirmedIndex == 0) != g.ConfirmedOn.IsZero() || g.ConfirmedOn.After(now) || (!g.ConfirmedOn.IsZero() && g.ConfirmedOn.Year() < 1970) || (g.ConfirmedIndex != 0 && indices[g.ConfirmedIndex]) {
			return fmt.Errorf("path: invalid guard confirmation")
		}
		if g.ConfirmedIndex == ^uint64(0) {
			return fmt.Errorf("path: exhausted confirmation index")
		}
		for _, n := range []float64{g.PathBias.UseAttempts, g.PathBias.UseSuccesses, g.PathBias.CircAttempts, g.PathBias.CircSuccesses, g.PathBias.SuccessfulCircuitsClosed, g.PathBias.CollapsedCircuits, g.PathBias.UnusableCircuits, g.PathBias.Timeouts} {
			if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
				return fmt.Errorf("path: invalid path-bias counter")
			}
		}
		if g.PathBias.UseSuccesses > g.PathBias.UseAttempts || g.PathBias.CircSuccesses > g.PathBias.CircAttempts {
			return fmt.Errorf("path: inconsistent path-bias counters")
		}
		if g.ConfirmedIndex != 0 {
			indices[g.ConfirmedIndex] = true
		}
	}
	return nil
}

func (m *GuardManager) save(ctx context.Context, next GuardSnapshot) error {
	data, err := json.Marshal(next)
	if err == nil {
		err = m.persistence.Save(ctx, data)
	}
	if err != nil {
		m.failure = fmt.Errorf("path: persist guards (manager disabled): %w", err)
		return m.failure
	}
	m.state = next
	return nil
}
func (m *GuardManager) record(id [20]byte) *GuardRecord {
	for i := range m.state.Guards {
		if m.state.Guards[i].Identity == id {
			return &m.state.Guards[i]
		}
	}
	return nil
}
func (m *GuardManager) relay(id [20]byte) *common.RouterStatus {
	if m.directory == nil {
		return nil
	}
	for i := range m.directory.list {
		r := &m.directory.list[i]
		if r.NodeID == id {
			return r
		}
	}
	return nil
}
func (m *GuardManager) filtered(id [20]byte) bool {
	g := m.record(id)
	r := m.relay(id)
	return g != nil && g.Listed && !g.PathBias.Disabled && r != nil && guardValideFunc(*r) && r.StatusFlags[common.FLAG_RUNNING] && r.StatusFlags[common.FLAG_VALID]
}
func containsGuard(ids [][20]byte, id [20]byte) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func (m *GuardManager) preference() [][20]byte {
	ids := make([][20]byte, 0, len(m.state.Guards))
	for _, g := range m.state.Guards {
		if m.filtered(g.Identity) {
			ids = append(ids, g.Identity)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool {
		a, b := m.record(ids[i]), m.record(ids[j])
		if a.ConfirmedIndex != 0 || b.ConfirmedIndex != 0 {
			return a.ConfirmedIndex != 0 && (b.ConfirmedIndex == 0 || a.ConfirmedIndex < b.ConfirmedIndex)
		}
		ar, br := m.runtime[a.Identity], m.runtime[b.Identity]
		if ar.pending != br.pending {
			return ar.pending
		}
		return ar.pending && ar.lastTried.Before(br.lastTried)
	})
	return ids
}
func (m *GuardManager) primaries() {
	next := make([][20]byte, 0, 3)
	for _, id := range m.preference() {
		if m.record(id).ConfirmedIndex != 0 && len(next) < 3 {
			next = append(next, id)
		}
	}
	for _, id := range m.primary {
		if len(next) < 3 && m.filtered(id) && !containsGuard(next, id) {
			next = append(next, id)
		}
	}
	for _, g := range m.state.Guards {
		if len(next) < 3 && m.filtered(g.Identity) && !containsGuard(next, g.Identity) {
			next = append(next, g.Identity)
		}
	}
	m.primary = next
}
func randomDuration(max time.Duration) (time.Duration, error) {
	n, e := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if e != nil {
		return 0, e
	}
	return time.Duration(n.Int64()), nil
}

// Reconcile uses only the defensive authenticated hydration, never exported
// mutable consensus fields. Expiry/unlisting is evaluated only with live state.
func (m *GuardManager) reconcile(ctx context.Context, cns *common.Consensus) error {
	if m.failure != nil {
		return m.failure
	}
	sl := New(cns, true)
	if err := sl.checkConsensus(); err != nil {
		return err
	}
	if sl.consensus.Parameter("pb_dropguards", 0, 0, 1) != 0 {
		return ErrGuardPathBias
	}
	if !m.state.LastValidAfter.IsZero() && sl.consensus.ValidAfter.Before(m.state.LastValidAfter) {
		return fmt.Errorf("path: consensus predates persisted guard directory epoch")
	}
	now := m.now()
	next := m.state
	next.LastValidAfter = sl.consensus.ValidAfter
	next.Guards = append([]GuardRecord(nil), m.state.Guards...)
	guards := make(map[[20]byte]*common.RouterStatus)
	for i := range sl.list {
		r := &sl.list[i]
		if guardValideFunc(*r) && r.StatusFlags[common.FLAG_RUNNING] && r.StatusFlags[common.FLAG_VALID] {
			guards[r.NodeID] = r
		}
	}
	changed := !next.LastValidAfter.Equal(m.state.LastValidAfter)
	kept := next.Guards[:0]
	for _, g := range next.Guards {
		listed := guards[g.Identity] != nil
		if listed != g.Listed {
			changed = true
			g.Listed = listed
			if listed {
				g.UnlistedSince = time.Time{}
			} else {
				d, e := randomDuration(4 * 24 * time.Hour)
				if e != nil {
					return e
				}
				g.UnlistedSince = sl.consensus.ValidAfter.Add(-d)
			}
		}
		expired := !g.Listed && now.Sub(g.UnlistedSince) > 20*24*time.Hour || g.ConfirmedIndex == 0 && now.Sub(g.SampledOn) > 120*24*time.Hour || g.ConfirmedIndex != 0 && now.Sub(g.ConfirmedOn) > 60*24*time.Hour
		if expired {
			changed = true
			continue
		}
		kept = append(kept, g)
	}
	next.Guards = kept
	limit := max(20, min(60, len(guards)/5))
	usable := 0
	sampled := make(map[[20]byte]bool)
	for _, g := range next.Guards {
		sampled[g.Identity] = true
		rt := m.runtime[g.Identity]
		if g.Listed && !g.PathBias.Disabled && (rt == nil || rt.reachable != -1) {
			usable++
		}
	}
	for usable < 20 && len(next.Guards) < limit {
		r, e := samplePublicGuard(sl, sampled)
		if e != nil {
			remaining := false
			for id := range guards {
				if !sampled[id] {
					remaining = true
				}
			}
			if !remaining {
				break
			}
			return e
		}
		d, e := randomDuration(12 * 24 * time.Hour)
		if e != nil {
			return e
		}
		next.Guards = append(next.Guards, GuardRecord{Identity: r.NodeID, SampledOn: now.Add(-d), SampledBy: "gonion-guards-v1", Listed: true})
		sampled[r.NodeID] = true
		usable++
		changed = true
	}
	if changed {
		if e := m.save(ctx, next); e != nil {
			return e
		}
	}
	m.directory = sl
	for _, g := range m.state.Guards {
		if m.runtime[g.Identity] == nil {
			m.runtime[g.Identity] = &guardRuntime{}
		}
	}
	m.primaries()
	for id, rt := range m.runtime {
		if m.record(id) == nil {
			delete(m.runtime, id)
			continue
		}
		if rt.reachable == -1 && !now.Before(rt.retryAt) {
			rt.reachable = 0
		}
	}
	return nil
}

// GuardLease owns one build and its fixed tail restriction. Close releases the
// lease without a reachability inference. Succeeded must finish before exposing
// the circuit to streams or onion-service control messages.
type GuardLease struct {
	manager             *GuardManager
	identity            [20]byte
	relay               *common.RouterStatus
	tail                *common.RouterStatus
	primary             bool
	selected, waiting   time.Time
	pendingGeneration   uint64
	terminal, succeeded bool
	// Path-bias counters are fate-sharing bookkeeping for one circuit, so each
	// event is recorded at most once even when callers race or re-fire.
	biasBuild, biasUse, biasClosed bool
	// biasSkip suppresses every path-bias counter mutation for a circuit whose
	// purpose C's pathbias_should_count excludes. The lease lifecycle
	// (Succeeded/Wait/Unreachable/Close) is unaffected; only counter
	// persistence is skipped.
	biasSkip bool
}

// BuildPurpose selects the path-bias accounting policy for one guarded build,
// mirroring C's circuit purpose gate in circpathbias.c:pathbias_should_count.
// Purposes that C does not count (client/service rendezvous join, client
// introduction, testing, controller) skip every path-bias counter while their
// guard-lease lifecycle still runs normally.
type BuildPurpose uint8

const (
	// PurposeCounted is the default: exit, HSDir fetch, client rendezvous
	// point, service introduction and service publication circuits, all counted
	// by C's path-bias accounting.
	PurposeCounted BuildPurpose = iota
	// PurposeRendezvousJoin skips accounting: C excludes
	// CIRCUIT_PURPOSE_S_CONNECT_REND and CIRCUIT_PURPOSE_S_REND_JOINED, the
	// service-side rendezvous join and the client's connection to the
	// rendezvous point reached through a client-built circuit.
	PurposeRendezvousJoin
	// PurposeClientIntro skips accounting: C excludes the introduction-point
	// build (CIRCUIT_PURPOSE_C_INTRODUCING..CIRCUIT_PURPOSE_C_INTRODUCE_ACKED)
	// that sends INTRODUCE1 toward a service's introduction point.
	PurposeClientIntro
)

func (l *GuardLease) Relay() *common.RouterStatus { return common.CloneRouter(l.relay) }
func (m *GuardManager) allowed(id [20]byte, tail *common.RouterStatus) bool {
	return m.filtered(id) && !m.directory.relaysConflict(m.relay(id), tail)
}

// Select is traffic-only: anonymous multi-hop HS directory circuits are traffic,
// not one-hop directory guards. Bootstrap is deliberately outside this manager.
func (m *GuardManager) Select(ctx context.Context, cns *common.Consensus, tail *common.RouterStatus, purpose ...BuildPurpose) (*GuardLease, error) {
	p := PurposeCounted
	if len(purpose) > 0 {
		p = purpose[0]
	}
	if m == nil || m.now == nil || m.persistence.Load == nil || m.persistence.Save == nil || m.runtime == nil {
		return nil, ErrGuardPersistence
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.reconcile(ctx, cns); e != nil {
		return nil, e
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := common.CloneRouter(tail)
	if target != nil {
		if !haveAllKeys(target) {
			return nil, fmt.Errorf("path: invalid guard tail restriction")
		}
		for i := range m.directory.list {
			r := &m.directory.list[i]
			if r.NodeID == target.NodeID {
				if !bytes.Equal(r.IdEd25519, target.IdEd25519) {
					return nil, fmt.Errorf("path: conflicting tail identity")
				}
				target.Family = r.Family
				target.Familys = r.Familys
				target.Ipv6Addr = r.Ipv6Addr
				break
			}
		}
	}
	now := m.now()
	for pass := 0; pass < 2; pass++ {
		chosen, primary := m.chooseGuard(target)
		if chosen != [20]byte{} {
			rt := m.runtime[chosen]
			rt.lastTried = now
			if !primary {
				if !rt.pending {
					rt.pending = true
					rt.pendingSince = now
					rt.pendingGeneration++
				}
				rt.pendingAttempts++
			}
			return &GuardLease{manager: m, identity: chosen, relay: common.CloneRouter(m.relay(chosen)), tail: common.CloneRouter(target), primary: primary, selected: now, pendingGeneration: rt.pendingGeneration, biasSkip: p != PurposeCounted}, nil
		}
		anyUsable := false
		for _, id := range m.preference() {
			if m.runtime[id].reachable != -1 {
				anyUsable = true
			}
		}
		if anyUsable {
			break
		}
		for _, rt := range m.runtime {
			rt.reachable = 0
		}
	}
	return nil, fmt.Errorf("path: no usable public guard for restriction")
}

func (m *GuardManager) chooseGuard(target *common.RouterStatus) ([20]byte, bool) {
	var chosen [20]byte
	primary := false
	// NUM_USABLE_PRIMARY_GUARDS is one: fallback to the first reachable
	// primary satisfying the restriction if the preferred one conflicts.
	for _, id := range m.primary {
		if m.runtime[id].reachable != -1 && m.allowed(id, target) {
			chosen = id
			primary = true
			break
		}
	}
	// Confirmed guards take precedence even when they are all pending.
	// Only if none is eligible may we explore an unconfirmed guard.
	if chosen == [20]byte{} {
		for _, id := range m.preference() {
			rt := m.runtime[id]
			if m.record(id).ConfirmedIndex != 0 && rt.reachable != -1 && !rt.pending && m.allowed(id, target) {
				chosen = id
				break
			}
		}
	}
	if chosen == [20]byte{} {
		for _, id := range m.preference() {
			rt := m.runtime[id]
			if m.record(id).ConfirmedIndex != 0 && rt.reachable != -1 && m.allowed(id, target) {
				chosen = id
				break
			}
		}
	}
	if chosen == [20]byte{} {
		for _, id := range m.preference() {
			rt := m.runtime[id]
			if m.record(id).ConfirmedIndex == 0 && rt.reachable != -1 && !rt.pending && m.allowed(id, target) {
				chosen = id
				break
			}
		}
	}
	return chosen, primary
}
func (l *GuardLease) Close() {
	if l == nil {
		return
	}
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.terminal {
		return
	}
	l.terminal = true
	if rt := m.runtime[l.identity]; rt != nil && !l.primary && rt.pending && rt.pendingGeneration == l.pendingGeneration {
		rt.pendingAttempts--
		if rt.pendingAttempts == 0 {
			rt.pending = false
			rt.pendingSince = time.Time{}
		}
	}
}

// Unreachable may be used only for an attributable guard connection failure,
// never for context cancellation, arbitrary extension failure or stream failure.
func (l *GuardLease) Unreachable() error {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.terminal || l.succeeded {
		return fmt.Errorf("path: guard lease already completed")
	}
	l.terminal = true
	rt := m.runtime[l.identity]
	if rt == nil {
		return nil
	}
	now := m.now()
	rt.reachable = -1
	rt.pending = false
	rt.pendingAttempts = 0
	rt.pendingGeneration++
	rt.pendingSince = time.Time{}
	if rt.failingSince.IsZero() {
		rt.failingSince = now
	}
	base, cap := 10*time.Minute, 36*time.Hour
	if containsGuard(m.primary, l.identity) {
		base, cap = 30*time.Second, 6*time.Hour
	}
	// dir-spec 5.5: lower=base, upper=max(lower+1s, previous*3).
	// For a first failure previous is zero, so the initial window is
	// [base, base+1s), not a fabricated previous retry delay.
	upper := max(base+time.Second, rt.delay*3)
	d, e := randomDuration(upper - base)
	if e != nil {
		m.failure = e
		return e
	}
	rt.delay = min(cap, base+d)
	rt.retryAt = rt.lastTried.Add(rt.delay)
	return nil
}
func (l *GuardLease) Succeeded(ctx context.Context) error {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.terminal || l.succeeded {
		return fmt.Errorf("path: guard lease already completed")
	}
	if m.failure != nil {
		return m.failure
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	g := m.record(l.identity)
	if g == nil {
		return fmt.Errorf("path: sampled guard expired during build")
	}
	if g.ConfirmedIndex == 0 {
		next := m.state
		next.Guards = append([]GuardRecord(nil), m.state.Guards...)
		idx := uint64(1)
		for _, g := range next.Guards {
			idx = max(idx, g.ConfirmedIndex+1)
		}
		d, e := randomDuration(12 * 24 * time.Hour)
		if e != nil {
			return e
		}
		for i := range next.Guards {
			if next.Guards[i].Identity == l.identity {
				next.Guards[i].ConfirmedIndex = idx
				next.Guards[i].ConfirmedOn = m.now().Add(-d)
			}
		}
		if e := m.save(ctx, next); e != nil {
			return e
		}
	}
	rt := m.runtime[l.identity]
	rt.reachable = 1
	rt.pending = false
	rt.pendingAttempts = 0
	rt.pendingGeneration++
	rt.pendingSince = time.Time{}
	rt.failingSince = time.Time{}
	rt.delay = 0
	rt.retryAt = time.Time{}
	now := m.now()
	if !l.primary && now.Sub(m.lastInternet) > 10*time.Minute {
		for _, id := range m.primary {
			m.runtime[id].reachable = 0
		}
	}
	m.lastInternet = now
	l.succeeded = true
	l.waiting = now
	// NO_CIRCLIST: re-derived primary guards are always usable. The C reference
	// also promotes newly confirmed primaries in entry_guards_note_guard_success.
	m.primaries()
	return nil
}

// biasCounters persists one path-bias mutation for this lease's guard. It
// returns success without writing when the sampled guard expired while the
// circuit lived: the record and its counters are already gone. A failed Save
// poisons the manager exactly like a failed confirmation.
func (l *GuardLease) biasCounters(update func(*GuardPathBias), once *bool) error {
	if l == nil || l.manager == nil {
		return fmt.Errorf("path: guard lease has no manager")
	}
	if l.biasSkip {
		// C's pathbias_should_count excludes this circuit purpose: persist no
		// counters. The lease lifecycle (Succeeded/Wait/Unreachable/Close) is
		// unchanged; only counter persistence is skipped.
		return nil
	}
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if *once {
		return nil
	}
	if m.failure != nil {
		return m.failure
	}
	g := m.record(l.identity)
	if g == nil {
		// C skips accounting when entry_guard_get_by_id_digest returns NULL.
		*once = true
		return nil
	}
	next := m.state
	next.Guards = append([]GuardRecord(nil), m.state.Guards...)
	var record *GuardRecord
	for i := range next.Guards {
		if next.Guards[i].Identity == l.identity {
			record = &next.Guards[i]
			break
		}
	}
	if record == nil {
		*once = true
		return nil
	}
	update(&record.PathBias)
	if err := m.save(context.Background(), next); err != nil {
		return err
	}
	*once = true
	return nil
}

// PathBiasBuildSucceeded counts a completed guarded multi-hop build: one
// construction attempt up to the guarded two-hop point and one success at the
// completed build (path-spec §7.1). It never touches reachability state.
func (l *GuardLease) PathBiasBuildSucceeded() error {
	return l.biasCounters(func(b *GuardPathBias) { b.CircAttempts++; b.CircSuccesses++ }, &l.biasBuild)
}

// PathBiasBuildAttempted counts one construction attempt for a build that
// failed after the second hop opened (a processed CREATED/EXTENDED reply, C
// circuit_finish_handshake). Circuit build failures before that point — a
// guard-connection or first-hop handshake failure — are not path bias and
// count no attempt (path-spec §7.1).
func (l *GuardLease) PathBiasBuildAttempted() error {
	return l.biasCounters(func(b *GuardPathBias) { b.CircAttempts++ }, &l.biasBuild)
}

// PathBiasBuildTimedOut counts the right-censored build timeout observed at the
// builder's fixed timeout as one attempt and one timeout (path-spec §7.1).
func (l *GuardLease) PathBiasBuildTimedOut() error {
	return l.biasCounters(func(b *GuardPathBias) { b.CircAttempts++; b.Timeouts++ }, &l.biasBuild)
}

// PathBiasUseAttempted counts one usage attempt: the first stream attachment
// on a completed circuit; later attachments on the same circuit do not repeat
// it (path-spec §7.2).
func (l *GuardLease) PathBiasUseAttempted() error {
	return l.biasCounters(func(b *GuardPathBias) { b.UseAttempts++ }, &l.biasUse)
}

// PathBiasCircuitClosed records the terminal close classification selected by
// the circuit wrapper: closed-and-unused, collapsed, unusable, or a finalized
// usage success with the successful close. Path-bias counters are not guard
// reachability; nothing here changes the reachability or confirmation state.
func (l *GuardLease) PathBiasCircuitClosed(kind PathBiasClose) error {
	return l.biasCounters(func(b *GuardPathBias) {
		switch kind {
		case PathBiasClientClose:
			b.SuccessfulCircuitsClosed++
		case PathBiasPrematureClose:
			b.CollapsedCircuits++
		case PathBiasUseSuccess:
			b.SuccessfulCircuitsClosed++
			b.UseSuccesses++
		case PathBiasUseFailed:
			b.UnusableCircuits++
		}
	}, &l.biasClosed)
}

// Wait implements guard-spec NO_CIRCLIST, retaining this circuit's restriction.
// The circuit remains owned but unused until promotion, timeout or cancellation.
func (l *GuardLease) Wait(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		m := l.manager
		m.mu.Lock()
		err := m.failure
		usable := containsGuard(m.primary, l.identity)
		if l.terminal || !l.succeeded {
			err = fmt.Errorf("path: guard circuit is not completed")
		} else if !m.filtered(l.identity) || m.directory == nil || !m.directory.consensus.IsLive(m.now()) {
			err = fmt.Errorf("path: guard directory expired or guard is no longer usable")
		}
		if err == nil && !usable {
			if m.now().Sub(l.waiting) > 10*time.Minute {
				err = fmt.Errorf("path: non-primary guard waiting timeout")
			} else {
				// NO_CIRCLIST is an alternative to UPDATE_WAITING: only
				// earlier suitable guards block this circuit. Do not add
				// UPDATE_WAITING's all-primary-down rule on top.
				usable = true
				for _, id := range m.preference() {
					if id == l.identity {
						break
					}
					rt := m.runtime[id]
					if m.allowed(id, l.tail) && rt.reachable != -1 && (!rt.pending || m.now().Sub(rt.pendingSince) < 15*time.Second) {
						usable = false
						break
					}
				}
			}
		}
		m.mu.Unlock()
		if err != nil {
			return err
		}
		if usable {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
