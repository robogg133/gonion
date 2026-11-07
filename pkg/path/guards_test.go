package path

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

func guardStore(data *[]byte, saveErr *error) GuardPersistence {
	return GuardPersistence{
		Load: func(context.Context) ([]byte, error) { return bytes.Clone(*data), nil },
		Save: func(_ context.Context, b []byte) error {
			if saveErr != nil && *saveErr != nil {
				return *saveErr
			}
			*data = bytes.Clone(b)
			return nil
		},
	}
}
func newGuardFixture(t *testing.T) (*GuardManager, *common.Consensus, *[]byte) {
	t.Helper()
	data := new([]byte)
	m, e := NewGuardManager(context.Background(), guardStore(data, nil))
	if e != nil {
		t.Fatal(e)
	}
	return m, testutil.Consensus(t, time.Now()), data
}

// guard-spec SAMPLED, CONFIRMED, PRIMARY and persistent-state. This fixture is
// signed and hydrated from the shared hash-checked Chutney descriptor fixture.
func TestGuardsDurableRestart(t *testing.T) {
	m, cns, data := newGuardFixture(t)
	ctx := context.Background()
	lease, e := m.Select(ctx, cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.state.Guards) != 2 || len(*data) == 0 {
		t.Fatal("sample was exposed without persistence")
	}
	original := lease.Relay()
	copyRelay := lease.Relay()
	copyRelay.NodeID = [20]byte{99}
	copyRelay.IdEd25519[0] ^= 1
	if lease.Relay().NodeID != original.NodeID || !bytes.Equal(lease.Relay().IdEd25519, original.IdEd25519) {
		t.Fatal("mutable relay escaped")
	}
	if e = lease.Succeeded(ctx); e != nil {
		t.Fatal(e)
	}
	if e = lease.Wait(ctx); e != nil {
		t.Fatal(e)
	}
	lease.Close()
	restarted, e := NewGuardManager(ctx, guardStore(data, nil))
	if e != nil {
		t.Fatal(e)
	}
	next, e := restarted.Select(ctx, cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if next.Relay().NodeID != original.NodeID {
		t.Fatal("confirmed guard changed on restart")
	}
	if restarted.runtime[original.NodeID].reachable != 0 {
		t.Fatal("reachability persisted")
	}
}

// Multiple pending builds of the same non-primary guard must not release
// each other's eligibility state when an earlier attempt is canceled.
func TestPendingGuardLeaseOwnership(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	first, err := m.Select(context.Background(), cns, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	id := m.state.Guards[0].Identity
	rt := m.runtime[id]
	rt.pending, rt.pendingAttempts, rt.pendingGeneration = true, 2, 3
	rt.pendingSince = time.Now()
	one := &GuardLease{manager: m, identity: id, pendingGeneration: 3}
	two := &GuardLease{manager: m, identity: id, pendingGeneration: 3}
	stale := &GuardLease{manager: m, identity: id, pendingGeneration: 2}
	stale.Close()
	one.Close()
	if !rt.pending || rt.pendingAttempts != 1 {
		t.Fatal("one canceled build cleared another pending build")
	}
	two.Close()
	if rt.pending || rt.pendingAttempts != 0 {
		t.Fatal("last build left guard pending")
	}
}

func TestGuardsLoadValidation(t *testing.T) {
	now := time.Now()
	base := GuardSnapshot{Version: 1, Instance: "public-default", Guards: []GuardRecord{{Identity: [20]byte{1}, SampledOn: now.Add(-time.Hour), SampledBy: "test", Listed: true}}}
	for _, tc := range []struct {
		name   string
		change func(*GuardSnapshot)
	}{
		{"version", func(s *GuardSnapshot) { s.Version = 2 }},
		{"instance", func(s *GuardSnapshot) { s.Instance = "bridge" }},
		{"identity", func(s *GuardSnapshot) { s.Guards[0].Identity = [20]byte{} }},
		{"duplicate", func(s *GuardSnapshot) { s.Guards = append(s.Guards, s.Guards[0]) }},
		{"future", func(s *GuardSnapshot) { s.Guards[0].SampledOn = now.Add(time.Hour) }},
		{"unlisted", func(s *GuardSnapshot) { s.Guards[0].Listed = false }},
		{"confirmation", func(s *GuardSnapshot) { s.Guards[0].ConfirmedIndex = 1 }},
		{"negative-counter", func(s *GuardSnapshot) { s.Guards[0].PathBias.UseAttempts = -1 }},
		{"counter-order", func(s *GuardSnapshot) { s.Guards[0].PathBias.UseSuccesses = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.Guards = append([]GuardRecord(nil), base.Guards...)
			tc.change(&s)
			b, _ := json.Marshal(s)
			if _, e := NewGuardManager(context.Background(), guardStore(&b, nil)); e == nil {
				t.Fatal("corrupt state accepted")
			}
		})
	}
	for _, raw := range []string{"", "{}", "null", `{"version":1,"version":1,"instance":"public-default","guards":[]}`, `{"version":1,"instance":"public-default","guards":[],"future":true}`, `{"version":1,"instance":"public-default","guards":[]} {}`} {
		b := []byte(raw)
		if _, e := NewGuardManager(context.Background(), guardStore(&b, nil)); e == nil {
			t.Fatalf("invalid state accepted: %s", raw)
		}
	}
	if _, e := NewGuardManager(context.Background(), GuardPersistence{}); !errors.Is(e, ErrGuardPersistence) {
		t.Fatal(e)
	}
	boom := errors.New("load failure")
	if _, e := NewGuardManager(context.Background(), GuardPersistence{Load: func(context.Context) ([]byte, error) { return nil, boom }, Save: func(context.Context, []byte) error { return nil }}); !errors.Is(e, boom) {
		t.Fatal(e)
	}
}

func TestGuardsRejectAmbiguousIdentityJSON(t *testing.T) {

	base := GuardSnapshot{Version: 1, Instance: "public-default", Guards: []GuardRecord{{Identity: [20]byte{1}, SampledOn: time.Now().Add(-time.Hour), SampledBy: "test", Listed: true}}}
	valid, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGuardManager(context.Background(), guardStore(&valid, nil)); err != nil {
		t.Fatalf("legacy snapshot without epoch rejected: %v", err)
	}

	prefix := `"identity":[`
	start := strings.Index(string(valid), prefix)
	if start < 0 {
		t.Fatal("missing identity")
	}
	end := strings.Index(string(valid)[start:], "]") + start + 1
	for _, tc := range []struct{ name, identity string }{
		{"short", `[1]`}, {"long", `[` + strings.Repeat(`1,`, 20) + `1]`},
		{"null", `null`}, {"string", `"AAAAAAAAAAAAAAAAAAAA"`},
		{"float", `[` + strings.Repeat(`1,`, 19) + `1.0]`},
		{"negative", `[` + strings.Repeat(`1,`, 19) + `-1]`},
		{"bool", `[` + strings.Repeat(`1,`, 19) + `true]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte(string(valid[:start+len(prefix)-1]) + tc.identity + string(valid[end:]))
			if _, err := NewGuardManager(context.Background(), guardStore(&b, nil)); err == nil {
				t.Fatal("accepted malformed identity")
			}
		})
	}
	for _, alias := range []string{`"Identity"`, `"IDENTITY"`, `"Version"`, `"Path_Bias"`, `"Use_Attempts"`} {
		b := []byte(strings.Replace(string(valid), `"identity"`, alias, 1))
		if alias == `"Version"` {
			b = []byte(strings.Replace(string(valid), `"version"`, alias, 1))
		}
		if alias == `"Path_Bias"` {
			b = []byte(strings.Replace(string(valid), `"path_bias"`, alias, 1))
		}
		if alias == `"Use_Attempts"` {
			b = []byte(strings.Replace(string(valid), `"use_attempts"`, alias, 1))
		}
		if _, err := NewGuardManager(context.Background(), guardStore(&b, nil)); err == nil {
			t.Fatalf("accepted alias %s", alias)
		}
	}
	alias := strings.Replace(string(valid), `"identity":`, `"Identity":[1],"identity":`, 1)
	b := []byte(alias)
	if _, err := NewGuardManager(context.Background(), guardStore(&b, nil)); err == nil {
		t.Fatal("accepted duplicate alias")
	}
}

func TestPendingConfirmedPrecedesFreeUnconfirmed(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	if err := m.reconcile(context.Background(), cns); err != nil {
		t.Fatal(err)
	}
	if len(m.state.Guards) != 2 {
		t.Fatal("fixture requires two signed guards")
	}
	confirmed, free := m.state.Guards[0].Identity, m.state.Guards[1].Identity
	m.record(confirmed).ConfirmedIndex = 1
	m.record(confirmed).ConfirmedOn = time.Now()
	m.runtime[confirmed].pending = true
	m.runtime[confirmed].pendingSince = time.Now()
	// Exercise the non-primary SELECTING branch with a validated directory.
	m.primary = nil
	got, primary := m.chooseGuard(nil)
	if primary || got != confirmed || got == free {
		t.Fatalf("selected %x instead of pending confirmed %x", got, confirmed)
	}
}

func TestGuardConsensusEpochRollback(t *testing.T) {
	m, old, data := newGuardFixture(t)
	ctx := context.Background()
	lease, err := m.Select(ctx, old, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	newer := testutil.Consensus(t, time.Now().Add(20*time.Minute))
	lease, err = m.Select(ctx, newer, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	saved := bytes.Clone(*data)
	if m.state.LastValidAfter.IsZero() {
		t.Fatal("missing persisted consensus epoch")
	}
	for _, manager := range []*GuardManager{m, func() *GuardManager {
		r, e := NewGuardManager(ctx, guardStore(data, nil))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}()} {
		if l, e := manager.Select(ctx, old, nil); l != nil || e == nil {
			t.Fatalf("older consensus accepted: %v", e)
		}
		if !bytes.Equal(saved, *data) {
			t.Fatal("rollback changed persisted history")
		}
		if l, e := manager.Select(ctx, newer, nil); e != nil {
			t.Fatalf("same authenticated epoch rejected: %v", e)
		} else {
			l.Close()
		}
	}
	future := m.state
	future.LastValidAfter = time.Now().Add(time.Hour)
	b, err := json.Marshal(future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGuardManager(ctx, guardStore(&b, nil)); err == nil {
		t.Fatal("accepted future directory epoch")
	}
}

func TestGuardsFailedSavePoisonsManager(t *testing.T) {
	m, cns, data := newGuardFixture(t)
	boom := errors.New("disk full")
	m.persistence = guardStore(data, &boom)
	if lease, e := m.Select(context.Background(), cns, nil); lease != nil || !errors.Is(e, boom) {
		t.Fatalf("selection exposed on failed save: %v", e)
	}
	if len(m.state.Guards) != 0 || len(*data) != 0 {
		t.Fatal("failed transaction published")
	}
	boom = nil
	if lease, e := m.Select(context.Background(), cns, nil); lease != nil || e == nil {
		t.Fatal("poisoned manager resumed")
	}
}

func TestGuardsFailedConfirmationNotExposed(t *testing.T) {
	m, cns, data := newGuardFixture(t)
	l, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	saved := bytes.Clone(*data)
	boom := errors.New("confirmation save failed")
	m.persistence = guardStore(data, &boom)
	if e = l.Succeeded(context.Background()); !errors.Is(e, boom) {
		t.Fatal(e)
	}
	if e = l.Wait(context.Background()); e == nil {
		t.Fatal("uncommitted confirmation became usable")
	}
	if !bytes.Equal(saved, *data) || m.record(l.identity).ConfirmedIndex != 0 {
		t.Fatal("failed confirmation published")
	}
}

// guard-spec ON_FAIL and appendices RETRY_SCHED; dir-spec 5.5. Cancellation
// releases pending state but never changes reachability or confirmation.
func TestGuardsCancellationAndRetry(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	l, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	id := l.identity
	l.Close()
	if m.runtime[id].reachable != 0 || m.record(id).ConfirmedIndex != 0 {
		t.Fatal("cancellation attributed to guard")
	}
	l, e = m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Unreachable(); e != nil {
		t.Fatal(e)
	}
	rt := m.runtime[l.identity]
	if rt.reachable != -1 || rt.failingSince.IsZero() || rt.delay < 30*time.Second || rt.delay >= 31*time.Second {
		t.Fatal("incorrect primary retry state")
	}
	if e = l.Unreachable(); e == nil {
		t.Fatal("lease outcome consumed twice")
	}
	next, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if next.identity == l.identity {
		t.Fatal("retried unreachable guard before schedule")
	}
}

func TestGuardsRestrictionAndTrust(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	ctx := context.Background()
	l, e := m.Select(ctx, cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	restricted, e := m.Select(ctx, cns, l.Relay())
	if e != nil {
		t.Fatal(e)
	}
	defer restricted.Close()
	if restricted.identity == l.identity {
		t.Fatal("tail restriction ignored")
	}
	cns.RelayInformation = nil
	cns.BandWidthWeight = common.BandWidthWeight{}
	another, e := m.Select(ctx, cns, nil)
	if e != nil {
		t.Fatal("mutable public model changed authorized state:", e)
	}
	another.Close()
	if _, e = m.Select(ctx, &common.Consensus{}, nil); e == nil {
		t.Fatal("untrusted directory accepted")
	}
	if _, e = (&GuardManager{}).Select(ctx, cns, nil); !errors.Is(e, ErrGuardPersistence) {
		t.Fatal(e)
	}
}

func TestGuardsConcurrentConfirmation(t *testing.T) {
	m, cns, data := newGuardFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, e := m.Select(context.Background(), cns, nil)
			if e != nil {
				t.Error(e)
				return
			}
			defer l.Close()
			if e = l.Succeeded(context.Background()); e != nil {
				t.Error(e)
				return
			}
			if e = l.Wait(context.Background()); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var s GuardSnapshot
	if e := decodeGuards(*data, &s, time.Now()); e != nil {
		t.Fatal(e)
	}
	confirmed := 0
	for _, g := range s.Guards {
		if g.ConfirmedIndex != 0 {
			confirmed++
		}
	}
	if confirmed != 1 {
		t.Fatalf("primary churn: confirmed %d guards", confirmed)
	}
}

// NO_CIRCLIST: run a transition trace directly so the waiting predicate can be
// checked independently of the fixture network's two-guard primary set.
func TestGuardsWaitingTrace(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	l, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	first := m.state.Guards[0].Identity
	second := m.state.Guards[1].Identity
	m.record(first).ConfirmedIndex = 1
	m.record(second).ConfirmedIndex = 2
	m.primary = [][20]byte{first}
	m.runtime[first].reachable = 1
	m.runtime[second].reachable = 1
	waiting := &GuardLease{manager: m, identity: second, relay: common.CloneRouter(m.relay(second)), succeeded: true, waiting: m.now()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = waiting.Wait(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("waiting circuit leaked: %v", e)
	}
	m.runtime[first].pending = true
	m.runtime[first].pendingSince = m.now().Add(-16 * time.Second)
	if e = waiting.Wait(context.Background()); e != nil {
		t.Fatal("expired earlier pending guard blocked:", e)
	}
	m.runtime[first].pending = false
	m.runtime[first].reachable = -1
	if e = waiting.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	m.runtime[first].reachable = 1
	waiting.tail = common.CloneRouter(m.relay(first))
	if e = waiting.Wait(context.Background()); e != nil {
		t.Fatal("incompatible earlier guard blocked:", e)
	}
	waiting.tail = nil
	waiting.waiting = m.now().Add(-11 * time.Minute)
	if e = waiting.Wait(context.Background()); e == nil {
		t.Fatal("idle timeout ignored")
	}
}

// path-spec §7 counter accounting: each lease event must map to exactly one
// counter mutation and never touch reachability or confirmation state.
func TestPathBiasCounterAccounting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lease func(l *GuardLease) error
		want  GuardPathBias
	}{
		{"build-succeeded", func(l *GuardLease) error { return l.PathBiasBuildSucceeded() }, GuardPathBias{CircAttempts: 1, CircSuccesses: 1}},
		{"build-attempted", func(l *GuardLease) error { return l.PathBiasBuildAttempted() }, GuardPathBias{CircAttempts: 1}},
		{"build-timed-out", func(l *GuardLease) error { return l.PathBiasBuildTimedOut() }, GuardPathBias{CircAttempts: 1, Timeouts: 1}},
		{"use-attempted", func(l *GuardLease) error { return l.PathBiasUseAttempted() }, GuardPathBias{UseAttempts: 1}},
		{"close-client", func(l *GuardLease) error { return l.PathBiasCircuitClosed(PathBiasClientClose) }, GuardPathBias{SuccessfulCircuitsClosed: 1}},
		{"close-premature", func(l *GuardLease) error { return l.PathBiasCircuitClosed(PathBiasPrematureClose) }, GuardPathBias{CollapsedCircuits: 1}},
		{"close-use-success", func(l *GuardLease) error { return l.PathBiasCircuitClosed(PathBiasUseSuccess) }, GuardPathBias{SuccessfulCircuitsClosed: 1, UseSuccesses: 1}},
		{"close-use-failed", func(l *GuardLease) error { return l.PathBiasCircuitClosed(PathBiasUseFailed) }, GuardPathBias{UnusableCircuits: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, cns, _ := newGuardFixture(t)
			l, e := m.Select(context.Background(), cns, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			if e = tc.lease(l); e != nil {
				t.Fatal(e)
			}
			if got := m.record(l.identity).PathBias; got != tc.want {
				t.Fatalf("counters %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPathBiasCountersPersist(t *testing.T) {
	m, cns, data := newGuardFixture(t)
	ctx := context.Background()
	l, e := m.Select(ctx, cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if e = l.PathBiasBuildSucceeded(); e != nil {
		t.Fatal(e)
	}
	if e = l.PathBiasUseAttempted(); e != nil {
		t.Fatal(e)
	}
	// A usage success may only be persisted while its attempt is already
	// durable: decodeGuards rejects successes above attempts.
	if e = l.PathBiasCircuitClosed(PathBiasUseSuccess); e != nil {
		t.Fatal(e)
	}
	var s GuardSnapshot
	if e = decodeGuards(*data, &s, m.now()); e != nil {
		t.Fatal(e)
	}
	for _, g := range s.Guards {
		if g.Identity != l.identity {
			continue
		}
		want := GuardPathBias{CircAttempts: 1, CircSuccesses: 1, UseAttempts: 1, UseSuccesses: 1, SuccessfulCircuitsClosed: 1}
		if g.PathBias != want {
			t.Fatalf("persisted counters %+v, want %+v", g.PathBias, want)
		}
	}
	restarted, e := NewGuardManager(ctx, guardStore(data, nil))
	if e != nil {
		t.Fatal(e)
	}
	if got := restarted.record(l.identity).PathBias; got.CircAttempts != 1 || got.UseAttempts != 1 {
		t.Fatalf("restart lost counters: %+v", got)
	}
}

func TestPathBiasEventsCountOncePerCircuit(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	l, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	for i := 0; i < 2; i++ {
		if e = l.PathBiasBuildSucceeded(); e != nil {
			t.Fatal(e)
		}
		if e = l.PathBiasUseAttempted(); e != nil {
			t.Fatal(e)
		}
	}
	if e = l.PathBiasCircuitClosed(PathBiasUseSuccess); e != nil {
		t.Fatal(e)
	}
	// The second close classification must not fire again, so the refused
	// PathBiasUseFailed close adds nothing beyond this accepted use success.
	if e = l.PathBiasCircuitClosed(PathBiasUseFailed); e != nil {
		t.Fatal(e)
	}
	want := GuardPathBias{CircAttempts: 1, CircSuccesses: 1, UseAttempts: 1, UseSuccesses: 1, SuccessfulCircuitsClosed: 1}
	if got := m.record(l.identity).PathBias; got != want {
		t.Fatalf("counters %+v, want %+v", got, want)
	}
}

// Mirror of C's NULL entry guard skip: a sampled guard that expired while the
// circuit lived drops its accounting silently.
func TestPathBiasExpiredGuardSkipsAccounting(t *testing.T) {
	m, cns, data := newGuardFixture(t)
	l, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.mu.Lock()
	m.state.Guards = nil
	m.mu.Unlock()
	saved := bytes.Clone(*data)
	for _, call := range []func(l *GuardLease) error{
		func(l *GuardLease) error { return l.PathBiasBuildSucceeded() },
		func(l *GuardLease) error { return l.PathBiasUseAttempted() },
		func(l *GuardLease) error { return l.PathBiasCircuitClosed(PathBiasUseFailed) },
	} {
		if e = call(l); e != nil {
			t.Fatal(e)
		}
	}
	if !bytes.Equal(saved, *data) {
		t.Fatal("expired guard accounting rewrote persisted state")
	}
}

func TestPathBiasFailedSavePoisonsAccounting(t *testing.T) {
	m, cns, _ := newGuardFixture(t)
	l, e := m.Select(context.Background(), cns, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	boom := errors.New("disk full")
	failure := &boom
	m.persistence = guardStore(&[]byte{}, failure)
	if e = l.PathBiasBuildSucceeded(); !errors.Is(e, boom) {
		t.Fatal(e)
	}
	if m.record(l.identity).PathBias.CircAttempts != 0 {
		t.Fatal("failed save applied counters")
	}
	if e = l.PathBiasUseAttempted(); !errors.Is(e, boom) {
		t.Fatal("poisoned manager resumed accounting:", e)
	}
}
