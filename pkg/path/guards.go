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

// ErrGuardPathBias rejects the only guard configuration this implementation
// cannot honor honestly: a consensus with pb_dropguards != 0. Dropping a guard
// for an extreme rate (path-spec §7.4) is evaluated against the usage success
// rate, and that rate is only meaningful when path-spec §7.2's close-time
// END-echo probe can rescue circuits whose streams failed while the path was
// healthy. The probe requires a structured RELAY_END with its nonce echo, which
// the capi circuit API cannot express (see PathBiasUseFailed), so enabling the
// action would disable guards from a measurement that systematically
// undercounts usage successes. The error is deliberately not relaxed: the
// configuration stays explicitly unsupported and fails closed (path-spec §7.5).
var ErrGuardPathBias = errors.New("path: pb_dropguards guard dropping is unsupported without the path-spec §7.2 END-echo probe")

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

// GuardPathBias retains counters across restarts and is the persisted input to
// path-spec §7.3 scaling and §7.4 rate evaluation: construction and usage
// attempts, successes, and the informational close classifications are
// recorded per lease from explicit events, never inferred from generic
// builder/stream errors. The §7.2 END-echo probe and the pb_dropguards disable
// action remain explicitly unsupported (ErrGuardPathBias); the rate tiers for
// the supported pb_dropguards=0 configuration are reported through
// GuardManager.SetPathBiasObserver.
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
	// Path-bias benefit-of-the-doubt bookkeeping (path-spec §7.3): how many
	// circuits through this guard currently hold counted-but-not-yet-closed
	// construction and usage attempts. Counts are transient, like C's
	// count_circs_in_states scan over the open circuit list.
	openBuilt, openUse int
	// biasTiers is the once-per-tier gate for path-spec §7.4 observations,
	// mirroring C's transient path_bias_{noticed,warned,extreme,...} flags.
	biasTiers uint8
}

// PathBiasClose is the terminal close classification of a guarded circuit
// whose build completed, per path-spec §7 and C's pathbias_check_close. The
// collapsed/unusable/timeouts counters are informational: the construction
// rate enforced by path-spec §7.4 is successful_circuits_closed (plus open
// circuits) over circ_attempts, exactly as C's pathbias_get_close_success_count.
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
	// usage attempt without recognized activity. path-spec §7.2 would send a
	// RELAY_BEGIN with a 0.a.b.c:25 nonce destination first and count a
	// nonce-matching RELAY_END as a usage success. This implementation cannot
	// verify that echo: the capi circuit API exposes neither the END payload
	// (RelayEndCell decoding keeps only the reason octet) nor a structured END
	// result from NewStream, and NewStream offers no interruptible probe
	// deadline (it can block for the full stream-open timeout inside Close).
	// No probe is sent and the bare attempt is counted directly as a
	// failure. The deviation is conservative — it never converts a failure
	// into a success — and it is why pb_dropguards enforcement stays
	// explicitly unsupported (ErrGuardPathBias).
	PathBiasUseFailed
)

// PathBiasThreshold is one path-spec §7.4 rate tier a guard's counters
// crossed. With the supported pb_dropguards=0 configuration the specified
// enforcement is warning-only: C Tor emits these as log messages, and Gonion
// reports each crossing once per guard and tier through
// GuardManager.SetPathBiasObserver.
type PathBiasThreshold uint8

const (
	// PathBiasNotice: construction close rate below pb_noticepct.
	PathBiasNotice PathBiasThreshold = iota + 1
	// PathBiasWarn: construction close rate below pb_warnpct.
	PathBiasWarn
	// PathBiasExtreme: construction close rate below pb_extremepct.
	PathBiasExtreme
	// PathBiasUseNotice: usage rate below pb_noticeusepct.
	PathBiasUseNotice
	// PathBiasUseExtreme: usage rate below pb_extremeusepct.
	PathBiasUseExtreme
)

// PathBiasObservation reports one threshold crossing. Successes is the
// numerator actually compared under path-spec §7.4: persisted successes plus
// the open-circuit benefit of the doubt. Attempts is the denominator at
// evaluation time; evaluation runs before the triggering increment, matching
// C's pathbias_measure_close_rate / pathbias_measure_use_rate call sites.
type PathBiasObservation struct {
	Identity  [20]byte
	Threshold PathBiasThreshold
	Attempts  float64
	Successes float64
}

// GuardManager implements the unrestricted public-default guard state. Pinned
// bridges do not use this manager. Path-bias accounting, scaling and rate
// observation are supplied by this manager; the pb_dropguards disable action
// fails explicitly (ErrGuardPathBias).
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
	// onPathBias receives path-spec §7.4 tier crossings; see
	// SetPathBiasObserver. Configure it before the first Select.
	onPathBias func(PathBiasObservation)
}

// SetPathBiasObserver registers the sink for path-spec §7.4 rate-tier
// observations (the supported configuration's warning-only enforcement). It is
// invoked synchronously under the manager lock, so — like GuardPersistence
// callbacks — it must not reenter the manager. A nil observer disables
// reporting. Tier crossings are transient and reported at most once per guard
// and tier per manager lifetime, mirroring C's path_bias_* flag gates.
func (m *GuardManager) SetPathBiasObserver(fn func(PathBiasObservation)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPathBias = fn
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
	// path-spec §7.4 pb_dropguards is the one unsupported bias configuration;
	// see pathBiasEnforcementSupported.
	if err := pathBiasEnforcementSupported(sl.consensus); err != nil {
		return err
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
			if !sampleableGuardRemaining(sl, guards, sampled) {
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

// sampleableGuardRemaining reports whether any unsampled relay could still be
// returned by samplePublicGuard. It must apply the exact same filters and
// weight test so a pool that is exhausted (or whose unsampled relays all have
// non-positive guard weight) is treated as termination, not a permanent wedge.
func sampleableGuardRemaining(sl *Selector, guards map[[20]byte]*common.RouterStatus, sampled map[[20]byte]bool) bool {
	for id, r := range guards {
		if sampled[id] || !guardValideFunc(*r) || !r.StatusFlags[common.FLAG_RUNNING] || !r.StatusFlags[common.FLAG_VALID] {
			continue
		}
		if weightedBandwidth(r.BandWidth, guardWeightFunc(r.StatusFlags, sl.weight)) > 0 {
			return true
		}
	}
	return false
}

// pathBiasEnforcementSupported rejects the consensus parameter configuration
// whose enforcement this implementation cannot reproduce: pb_dropguards != 0
// (path-spec §7.4). The disable action depends on the §7.2 END-echo usage
// probe, which the circuit API cannot express, so the configuration fails
// closed and never relaxes ErrGuardPathBias. With the supported default (0),
// §7.3 scaling and the §7.4 warning-only rate tiers run normally. Parameter
// clamping follows C's pathbias_get_dropguards: negative values clamp to 0
// (disabled) and are accepted; positive out-of-range values clamp to 1 and
// are rejected.
func pathBiasEnforcementSupported(cns *common.Consensus) error {
	if cns != nil && cns.Parameter("pb_dropguards", 0, 0, 1) != 0 {
		return ErrGuardPathBias
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
	// biasBuildOpen / biasUseOpen mirror registration in the manager's
	// open-circuit benefit-of-the-doubt counts (path-spec §7.3). They are set
	// only after the corresponding counter save succeeds and cleared when the
	// close classification is recorded or the lease is released.
	biasBuildOpen, biasUseOpen bool
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
	// SELECTING step 3: when every usable unconfirmed guard is already pending,
	// selecting a pending member in sample order is still specified; failing
	// here would wedge selection while leases are in flight.
	if chosen == [20]byte{} {
		for _, id := range m.preference() {
			rt := m.runtime[id]
			if m.record(id).ConfirmedIndex == 0 && rt.reachable != -1 && m.allowed(id, target) {
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
	// Releasing an unaccounted lease must not leave stale open-circuit
	// benefit-of-the-doubt counts behind; this is a no-op when the close
	// classification already ran.
	l.releaseOpenCounters()
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

// biasEvent identifies which path-spec §7 mutation a lease is persisting, so
// the §7.4 measurement and §7.3 scaling run at C's exact call sites: on every
// construction/usage attempt increment, before the increment, and never on a
// close classification.
type biasEvent uint8

const (
	// biasEventBuildFailed: a construction attempt whose build failed after
	// the second hop opened; the circuit is already gone.
	biasEventBuildFailed biasEvent = iota + 1
	// biasEventBuildSuccess: a completed build counted as attempt+success;
	// the circuit is open and belongs to the benefit-of-the-doubt set.
	biasEventBuildSuccess
	// biasEventUseAttempt: the circuit's first stream attachment; open.
	biasEventUseAttempt
	// biasEventClose: the terminal close classification.
	biasEventClose
)

// pathBiasParams carries the path-spec §7.4 consensus parameters with C Tor's
// circpathbias.c defaults and networkstatus_get_param clamps. C clamps the
// percentage parameters to [0,100] rather than the document's Min values so a
// zero rate can disable a tier; that deployed behavior is kept.
type pathBiasParams struct {
	minCircs, noticePct, warnPct, extremePct int
	minUse, noticeUsePct, extremeUsePct      int
	scaleCircs, scaleUse                     int
	scaleNumerator, scaleDenominator         int
}

func pathBiasRatio(p pathBiasParams) float64 {
	return float64(p.scaleNumerator) / float64(p.scaleDenominator)
}
func pathBiasPct(pct int) float64 { return float64(pct) / 100.0 }

// biasParams reads the parameters from the sealed consensus snapshot the last
// reconcile validated, falling back to the §7.4 defaults when no directory is
// attached yet.
func (m *GuardManager) biasParams() pathBiasParams {
	p := pathBiasParams{minCircs: 150, noticePct: 70, warnPct: 50, extremePct: 30, minUse: 20, noticeUsePct: 80, extremeUsePct: 60, scaleCircs: 300, scaleUse: 100, scaleNumerator: 1, scaleDenominator: 2}
	if m.directory == nil || m.directory.consensus == nil {
		return p
	}
	cns := m.directory.consensus
	p.minCircs = cns.Parameter("pb_mincircs", 150, 5, 1<<31-1)
	p.noticePct = cns.Parameter("pb_noticepct", 70, 0, 100)
	p.warnPct = cns.Parameter("pb_warnpct", 50, 0, 100)
	p.extremePct = cns.Parameter("pb_extremepct", 30, 0, 100)
	p.minUse = cns.Parameter("pb_minuse", 20, 3, 1<<31-1)
	p.noticeUsePct = cns.Parameter("pb_noticeusepct", 80, 0, 100)
	p.extremeUsePct = cns.Parameter("pb_extremeusepct", 60, 0, 100)
	p.scaleCircs = cns.Parameter("pb_scalecircs", 300, 10, 1<<31-1)
	p.scaleUse = cns.Parameter("pb_scaleuse", 100, 10, 1<<31-1)
	p.scaleDenominator = cns.Parameter("pb_scalefactor", 2, 2, 1<<31-1)
	p.scaleNumerator = cns.Parameter("pb_multfactor", 1, 1, int32(p.scaleDenominator))
	return p
}

// constructionTier evaluates the path-spec §7.4 construction close rate
// exactly as C's pathbias_measure_close_rate: strictly more than pb_mincircs
// attempts before evaluating, strictly-below tier comparisons (a rate exactly
// at a tier does not cross it), and worst-tier-only selection. The numerator
// is successful_circuits_closed plus open circuits between build success and
// close, C's pathbias_get_close_success_count.
func constructionTier(p pathBiasParams, b *GuardPathBias, openBuilt int) (PathBiasThreshold, bool) {
	if !(b.CircAttempts > float64(p.minCircs)) {
		return 0, false
	}
	rate := (b.SuccessfulCircuitsClosed + float64(openBuilt)) / b.CircAttempts
	switch {
	case rate < pathBiasPct(p.extremePct):
		return PathBiasExtreme, true
	case rate < pathBiasPct(p.warnPct):
		return PathBiasWarn, true
	case rate < pathBiasPct(p.noticePct):
		return PathBiasNotice, true
	}
	return 0, false
}

// usageTier is C's pathbias_measure_use_rate with the same strict comparisons;
// the numerator adds open usage-attempted circuits (pathbias_get_use_success_count).
func usageTier(p pathBiasParams, b *GuardPathBias, openUse int) (PathBiasThreshold, bool) {
	if !(b.UseAttempts > float64(p.minUse)) {
		return 0, false
	}
	rate := (b.UseSuccesses + float64(openUse)) / b.UseAttempts
	switch {
	case rate < pathBiasPct(p.extremeUsePct):
		return PathBiasUseExtreme, true
	case rate < pathBiasPct(p.noticeUsePct):
		return PathBiasUseNotice, true
	}
	return 0, false
}

// scaleConstruction applies path-spec §7.3 to the construction family when
// circ_attempts exceeds pb_scalecircs: open circuits are subtracted before
// scaling and added back after, so only closed history is decayed. Gonion has
// no pre-close USE_FAILED state, so every open counted circuit is in C's
// BUILD_ATTEMPTED..USE_FAILED subtraction set; a build attempt is only
// counted once the build has already terminated, hence no BUILD_ATTEMPTED
// window exists here. Both families keep successes <= attempts under the
// transform, so the persisted-state invariant survives scaling.
func scaleConstruction(p pathBiasParams, b *GuardPathBias, openBuilt int) {
	if !(b.CircAttempts > float64(p.scaleCircs)) {
		return
	}
	r := pathBiasRatio(p)
	o := float64(min(openBuilt, int(b.CircAttempts)))
	b.CircAttempts = (b.CircAttempts-o)*r + o
	b.CircSuccesses = (b.CircSuccesses-o)*r + o
	b.Timeouts *= r
	b.SuccessfulCircuitsClosed *= r
	b.CollapsedCircuits *= r
	b.UnusableCircuits *= r
}

// scaleUsage applies §7.3 to the usage family at pb_scaleuse. Only attempts
// carry the open-circuit subtraction in C's pathbias_scale_use_rates, and
// successes are decayed directly; the invariant holds because
// r*(attempts-successes) + open*(1-r) >= 0.
func scaleUsage(p pathBiasParams, b *GuardPathBias, openUse int) {
	if !(b.UseAttempts > float64(p.scaleUse)) {
		return
	}
	r := pathBiasRatio(p)
	o := float64(min(openUse, int(b.UseAttempts)))
	b.UseAttempts = (b.UseAttempts-o)*r + o
	b.UseSuccesses *= r
}

// biasCounters persists one path-bias mutation for this lease's guard,
// running the path-spec §7.4 measurement and §7.3 scaling before the
// triggering increment (C's pathbias_measure_*/pathbias_scale_* order). It
// returns success without writing when the sampled guard expired while the
// circuit lived: the record and its counters are already gone. A failed Save
// poisons the manager exactly like a failed confirmation; scale and measure
// results are discarded with the uncommitted copy, and the observation is
// reported only after the save commits.
func (l *GuardLease) biasCounters(event biasEvent, update func(*GuardPathBias), once *bool) error {
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
		if event == biasEventClose {
			l.releaseOpenCounters()
		}
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
	rt := m.runtime[l.identity]
	openBuilt, openUse := 0, 0
	if rt != nil {
		openBuilt, openUse = rt.openBuilt, rt.openUse
	}
	var observed PathBiasObservation
	switch event {
	case biasEventBuildFailed, biasEventBuildSuccess:
		p := m.biasParams()
		if tier, ok := constructionTier(p, &record.PathBias, openBuilt); ok && rt != nil && rt.biasTiers&(1<<tier) == 0 {
			observed = PathBiasObservation{Identity: l.identity, Threshold: tier, Attempts: record.PathBias.CircAttempts, Successes: record.PathBias.SuccessfulCircuitsClosed + float64(openBuilt)}
		}
		scaleConstruction(p, &record.PathBias, openBuilt)
	case biasEventUseAttempt:
		p := m.biasParams()
		if tier, ok := usageTier(p, &record.PathBias, openUse); ok && rt != nil && rt.biasTiers&(1<<tier) == 0 {
			observed = PathBiasObservation{Identity: l.identity, Threshold: tier, Attempts: record.PathBias.UseAttempts, Successes: record.PathBias.UseSuccesses + float64(openUse)}
		}
		scaleUsage(p, &record.PathBias, openUse)
	case biasEventClose:
		// C performs no measurement or scaling at close classification.
	}
	update(&record.PathBias)
	if err := m.save(context.Background(), next); err != nil {
		return err
	}
	*once = true
	if observed.Threshold != 0 {
		rt.biasTiers |= 1 << observed.Threshold
		if m.onPathBias != nil {
			m.onPathBias(observed)
		}
	}
	// Open-circuit registration for the §7.3 benefit of the doubt happens
	// only after the counters are durable, so the open set is always a subset
	// of the counted history.
	if rt != nil {
		switch event {
		case biasEventBuildSuccess:
			rt.openBuilt++
			l.biasBuildOpen = true
		case biasEventUseAttempt:
			rt.openUse++
			l.biasUseOpen = true
		}
	}
	if event == biasEventClose {
		l.releaseOpenCounters()
	}
	return nil
}

// releaseOpenCounters drops this lease from the manager's open-circuit counts
// once its close classification is durable, or when the lease is released
// without one. The manager lock must be held. Clamped at zero because a guard
// can expire and be re-sampled while its old circuits still close.
func (l *GuardLease) releaseOpenCounters() {
	if l == nil || l.manager == nil || (!l.biasBuildOpen && !l.biasUseOpen) {
		return
	}
	if rt := l.manager.runtime[l.identity]; rt != nil {
		if l.biasBuildOpen && rt.openBuilt > 0 {
			rt.openBuilt--
		}
		if l.biasUseOpen && rt.openUse > 0 {
			rt.openUse--
		}
	}
	l.biasBuildOpen, l.biasUseOpen = false, false
}

// PathBiasBuildSucceeded counts a completed guarded multi-hop build: one
// construction attempt up to the guarded two-hop point and one success at the
// completed build (path-spec §7.1). The circuit stays open, so it joins the
// §7.3 benefit-of-the-doubt set until its close classification. It never
// touches reachability state.
func (l *GuardLease) PathBiasBuildSucceeded() error {
	return l.biasCounters(biasEventBuildSuccess, func(b *GuardPathBias) { b.CircAttempts++; b.CircSuccesses++ }, &l.biasBuild)
}

// PathBiasBuildAttempted counts one construction attempt for a build that
// failed after the second hop opened (a processed CREATED/EXTENDED reply, C
// circuit_finish_handshake). Circuit build failures before that point — a
// guard-connection or first-hop handshake failure — are not path bias and
// count no attempt (path-spec §7.1).
func (l *GuardLease) PathBiasBuildAttempted() error {
	return l.biasCounters(biasEventBuildFailed, func(b *GuardPathBias) { b.CircAttempts++ }, &l.biasBuild)
}

// PathBiasBuildTimedOut counts the right-censored build timeout observed at the
// builder's fixed timeout as one attempt and one timeout (path-spec §7.1).
func (l *GuardLease) PathBiasBuildTimedOut() error {
	return l.biasCounters(biasEventBuildFailed, func(b *GuardPathBias) { b.CircAttempts++; b.Timeouts++ }, &l.biasBuild)
}

// PathBiasUseAttempted counts one usage attempt: the first stream attachment
// on a completed circuit; later attachments on the same circuit do not repeat
// it (path-spec §7.2). The open circuit joins the §7.3 usage benefit set until
// close.
func (l *GuardLease) PathBiasUseAttempted() error {
	return l.biasCounters(biasEventUseAttempt, func(b *GuardPathBias) { b.UseAttempts++ }, &l.biasUse)
}

// PathBiasCircuitClosed records the terminal close classification selected by
// the circuit wrapper: closed-and-unused, collapsed, unusable, or a finalized
// usage success with the successful close. Per path-spec §7.2 a bare usage
// attempt is probed with an END echo before classification; that probe is not
// expressible through the circuit API, so PathBiasUseFailed is the conservative
// direct classification. Path-bias counters are not guard reachability;
// nothing here changes the reachability or confirmation state.
func (l *GuardLease) PathBiasCircuitClosed(kind PathBiasClose) error {
	err := l.biasCounters(biasEventClose, func(b *GuardPathBias) {
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
	// biasCounters released the open-circuit registration under the manager
	// lock once the close classification committed; a failed save keeps it
	// until Close releases it against the poisoned manager.
	return err
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
