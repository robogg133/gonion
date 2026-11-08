package hs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
)

// fakeClock advances a wall clock atomically so tests can drive the renewal
// gates without sleeping through real backoff intervals.
type fakeClock struct {
	nanos atomic.Int64
}

func (c *fakeClock) Now() time.Time     { return time.Unix(0, c.nanos.Load()) }
func (c *fakeClock) Set(wall time.Time) { c.nanos.Store(wall.UnixNano()) }
func (c *fakeClock) Add(d time.Duration) {
	c.nanos.Store(c.Now().Add(d).UnixNano())
}

// waitUntil spins on an observable condition with a bounded deadline; it only
// reads mutex- or atomic-guarded state, so it never races the maintenance
// goroutine.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// storeRing returns the relay identities of one descriptor's store ring.
func (f *rolloverFixture) storeRing(t *testing.T, p descriptorPeriod) []common.RouterStatus {
	t.Helper()
	blinded, err := crypto.BlindPrivateKey(f.identity, p.number, p.length)
	if err != nil {
		t.Fatal(err)
	}
	cns := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	groups, err := hsdirReplicas(cns, blinded.PublicKey(), p.number, p.length, sharedRandom(cns, p.number, p.length, false), true)
	if err != nil {
		t.Fatal(err)
	}
	var out []common.RouterStatus
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// storeTailRelays returns the relay identities of the last replica group of
// each listed descriptor, mirroring the group structure publish() observes.
func (f *rolloverFixture) storeTailRelays(t *testing.T, cns *common.Consensus, periods [2]descriptorPeriod) map[[20]byte]bool {
	t.Helper()
	out := make(map[[20]byte]bool)
	for i, p := range periods {
		blinded, err := crypto.BlindPrivateKey(f.identity, p.number, p.length)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := hsdirReplicas(cns, blinded.PublicKey(), p.number, p.length, sharedRandom(cns, p.number, p.length, i == 1), true)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 2 {
			t.Fatalf("%d store replicas", len(groups))
		}
		for _, r := range groups[len(groups)-1] {
			out[r.NodeID] = true
		}
	}
	return out
}

// publishFailures marks the given relays so their uploads return HTTP 503
// until the test restores them.
func (f *rolloverFixture) publishFailures(nodeIDs map[[20]byte]bool, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for node := range nodeIDs {
		if status == 200 {
			delete(f.uploadStatus, node)
		} else {
			f.uploadStatus[node] = status
		}
	}
}

func maintenanceDescriptor(t *testing.T, p descriptorPeriod) *serviceDescriptor {
	t.Helper()
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	blinded, err := crypto.BlindPrivateKey(identity, p.number, p.length)
	if err != nil {
		t.Fatal(err)
	}
	d := &serviceDescriptor{period: p, blinded: blinded, signing: identity}
	for range 3 {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		d.intros = append(d.intros, &serviceIntroduction{circuit: &lifecycleCircuit{ctx: ctx, cancel: cancel}})
	}
	return d
}

func TestServiceRenewAttemptsBothDescriptors(t *testing.T) {
	// SERVICEUPLOAD requires both overlapping descriptors. Use the signed
	// Tor/Chutney-layout test directory; no network or trust bypass is used.
	cns := testutil.Consensus(t, time.Now())
	periods := servicePeriods(cns)
	first := maintenanceDescriptor(t, periods[0])
	second := maintenanceDescriptor(t, periods[1])
	l := &Listener{
		opts:        ServiceOptions{Identity: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))},
		consensus:   func() *common.Consensus { return cns },
		descriptors: map[descriptorPeriod]*serviceDescriptor{periods[0]: first, periods[1]: second},
		retries:     make(map[descriptorPeriod]periodRetry),
		revisions:   make(map[[32]byte]uint64),
	}
	// This signed fixture has no HSDirs: both independent descriptor attempts
	// must report that failure, rather than abandoning the second descriptor.
	err := l.renew(context.Background())
	if err == nil || strings.Count(err.Error(), "no HSDir=2 relays") != 2 {
		t.Fatalf("one descriptor failure suppressed the other: %v", err)
	}
}

func TestServiceRetiredExpiryWithoutConsensus(t *testing.T) {
	// EXPIRE-DESC retains introductions for 180 minutes after publication,
	// independently of whether new uploads can currently be authorized.
	now := time.Now()
	expired := maintenanceDescriptor(t, descriptorPeriod{16903, 1440})
	expired.published = now.Add(-4 * time.Hour)
	retained := maintenanceDescriptor(t, descriptorPeriod{16904, 1440})
	retained.published = now.Add(-2 * time.Hour)
	l := &Listener{consensus: func() *common.Consensus { return nil }, retired: []*serviceDescriptor{expired, retained}}
	backing := l.retired
	if err := l.renew(context.Background()); err == nil {
		t.Fatal("missing consensus authorized publication")
	}
	if len(l.retired) != 1 || l.retired[0] != retained {
		t.Fatal("expired introductions retained during directory outage")
	}
	for _, ip := range expired.intros {
		if ip.circuit.Ctx().Err() == nil {
			t.Fatal("expired introduction circuit left open")
		}
	}
	if !retained.healthy() {
		t.Fatal("still-valid published introductions closed early")
	}
	if !bytes.Equal(expired.signing, make([]byte, ed25519.PrivateKeySize)) || backing[1] != nil {
		t.Fatal("retired signing key or stale slice reference retained")
	}
}

// driveMaintenance starts the maintenance loop with injectable ticks and a
// fake wall clock; the returned tick func both advances time and signals one
// renewal cycle.
func driveMaintenance(t *testing.T, f *rolloverFixture, l *Listener, clock *fakeClock, wall time.Time) (func(time.Duration), chan struct{}) {
	t.Helper()
	clock.Set(wall)
	l.clock = clock.Now
	ticks := make(chan time.Time, 8)
	l.maintenanceTick = ticks
	done := make(chan struct{})
	go func() {
		l.maintain()
		close(done)
	}()
	t.Cleanup(func() { l.Shutdown() })
	return func(step time.Duration) {
		clock.Add(step)
		ticks <- time.Now()
	}, done
}

func TestServiceMaintenanceBoundedRebuildStorm(t *testing.T) {
	// An introduction relay that rejects every build cannot cause a full
	// storm on every maintenance tick: the per-period rebuild delay doubles
	// per consecutive failure, the operational error stays visible through
	// Err(), and no descriptor revision is reserved while nothing publishes.
	f := startRollover(t)
	cnsA := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	f.introFailure.Store(true)
	clock := &fakeClock{}
	l := f.newListener()
	l.consensus = func() *common.Consensus { return cnsA }
	tick, done := driveMaintenance(t, f, l, clock, cnsA.ValidAfter.Add(time.Minute))

	// The first renewal burns its bounded attempt budget (nine establishment
	// attempts per reshaped descriptor) and leaves the backoff error visible.
	// The first renewal burns its bounded attempt budget (six distinct test
	// relays reject every establishment) and leaves the failure visible. The
	// exact exhaustion text depends on the relay budget, so accept both
	// terminal shapes but never a nil error.
	tick(time.Minute)
	if !waitUntil(2*time.Second, func() bool { return f.builds.Load() >= 6 }) {
		t.Fatal("the first renewal did not exhaust the introduction budget")
	}
	if !waitUntil(2*time.Second, func() bool {
		err := l.Err()
		return err != nil && (strings.Contains(err.Error(), "introduction establishment attempts exhausted") || strings.Contains(err.Error(), "insufficient distinct introduction relays"))
	}) {
		t.Fatalf("no bounded rebuild error visible: %v", l.Err())
	}
	// From the second tick onward the failure is journaled as bounded retry
	// pacing instead of burning circuits every tick.
	tick(time.Minute)
	if !waitUntil(2*time.Second, func() bool {
		err := l.Err()
		return err != nil && strings.Contains(err.Error(), "introduction rebuild waits")
	}) {
		t.Fatalf("no bounded rebuild error visible: %v", l.Err())
	}

	// Simulated hours of failing maintenance: the rebuild storm repeats only
	// as the delay grows, never on every tick.
	for range 24 {
		tick(2 * time.Minute)
	}
	between := f.builds.Load()
	// Base 2 minutes doubling to 30: 2+4+8+16+... caps grown per failure so 24
	// driven ticks cannot re-issue the full storm more than a handful of
	// times, without any real wall-clock waiting.
	if between < 18 || between >= 24*9 {
		t.Fatalf("rebuild storm beyond bounds: %d circuit builds over 24 ticks", between)
	}
	if f.revisions.reservationCount() != 0 {
		t.Fatal("descriptor revisions reserved although nothing published")
	}
	// Shutdown terminates the maintenance goroutine over the injected tick
	// channel without touching accepted state.
	l.Shutdown()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance survived listener shutdown")
	}
}

func TestServiceMaintenancePartialAckRetryCycle(t *testing.T) {
	// One replica never acknowledges: each renewal reserves a bounded number
	// of revisions, keeps acknowledgements visible through Err(), and the
	// eventual repair makes the next cycle publish both descriptors and clear
	// the operational error.
	f := startRollover(t)
	cnsA := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	periodsA := servicePeriods(cnsA)
	f.blindFor(periodsA[0])
	f.blindFor(periodsA[1])

	// Fail every upload of the last replica group of both descriptors: that
	// replica can never acknowledge, so each publication reports failure.
	failing := f.storeTailRelays(t, cnsA, periodsA)
	f.publishFailures(failing, 503)

	clock := &fakeClock{}
	l := f.newListener()
	l.consensus = func() *common.Consensus { return cnsA }
	tick, _ := driveMaintenance(t, f, l, clock, cnsA.ValidAfter.Add(time.Minute))

	// First renewal: a partial publication. The failure is visible, one
	// revision per attempted period is reserved, and the unacknowledged group
	// delays any further upload.
	tick(time.Minute)
	if !waitUntil(2*time.Second, func() bool {
		err := l.Err()
		return err != nil && strings.Contains(err.Error(), "descriptor replica not published")
	}) {
		t.Fatalf("no bounded publication error visible: %v", l.Err())
	}
	firstCount := f.revisions.reservationCount()
	if firstCount != 2 {
		t.Fatalf("%d reservations for one failed publication (each period reserved once)", firstCount)
	}
	// The next tick journals the bounded retry pacing instead of uploading.
	tick(time.Minute)
	if !waitUntil(2*time.Second, func() bool {
		err := l.Err()
		return err != nil && strings.Contains(err.Error(), "descriptor upload waits")
	}) {
		t.Fatalf("no bounded publication error visible: %v", l.Err())
	}

	// A bounded randomized retry: no second full storm.
	for range 6 {
		tick(5 * time.Minute)
	}
	if churn := f.revisions.reservationCount(); churn > firstCount+2 {
		t.Fatalf("publication retries exhausted %d reservations, want bounded pacing", churn)
	}

	// Restore the relays: the repaired directory publishes on the bounded
	// retry schedule and clears the error surface once both replicas
	// acknowledge.
	f.publishFailures(failing, 200)
	for range 3 {
		tick(5 * time.Minute)
		if waitUntil(2*time.Second, func() bool { return l.Err() == nil }) {
			break
		}
	}
	if err := l.Err(); err != nil {
		t.Fatalf("successful renewal did not clear the error: %v", err)
	}

	// Steady state keeps the randomized publication interval in force: no
	// further reservations before the interval lapses.
	settled := f.revisions.reservationCount()
	for range 3 {
		tick(5 * time.Minute)
	}
	if churn := f.revisions.reservationCount(); churn != settled {
		t.Fatalf("steady-state maintenance reserved %d more revisions", churn-settled)
	}
}

func TestServiceMaintenanceCloseDuringInflightRenewal(t *testing.T) {
	// Closing the listener cancels an in-flight renewal instead of waiting for
	// it; no revision is reserved for work that never completed, and the
	// maintenance goroutine exits promptly.
	f := startRollover(t)
	cnsA := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	clock := &fakeClock{}
	l := f.newListener()
	l.consensus = func() *common.Consensus { return cnsA }
	var blocked atomic.Int32
	l.builder = guardedServiceBuild{serviceBuildFunc: func(ctx context.Context, _ []*common.RouterStatus) (capi.Circ, error) {
		blocked.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}, guards: f.guards}
	tick, done := driveMaintenance(t, f, l, clock, cnsA.ValidAfter.Add(time.Minute))

	tick(time.Minute)
	if !waitUntil(2*time.Second, func() bool { return blocked.Load() > 0 }) {
		t.Fatal("the in-flight renewal did not start building")
	}
	l.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance survived in-flight cancellation")
	}
	if f.revisions.reservationCount() != 0 {
		t.Fatal("an in-flight renewal burned descriptor revisions")
	}
}
