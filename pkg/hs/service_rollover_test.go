package hs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/internal/testutil/guardfixture"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
	"github.com/robogg133/gonion/pkg/path"
)

// H3.1 offline fixtures and tests. SRV values are 32-byte SHA-3 digests of
// fixed strings and relay identities come from a fixed relaySeed, so every
// run inspects exactly one authentication-valid HSDir ring. Nothing modifies a
// verified consensus: SRVs and identity flags travel inside the signed body.
// Time segments follow rend-spec-v3 FIRSTDESCUPLOAD/SECONDDESCUPLOAD:
//
//	00:00   12:00    00:00    12:00    00:00
//	SRV0====|--TP1--$SRV1====|--TP2--$SRV2 ...
//
//	epoch A (04-13 13:00): first=(TP1,SRV0) second=(TP2,SRV1)
//	epoch B (04-14 01:00): first=(TP2,SRV1) second=(TP3,SRV2)
type srvEpoch struct {
	validAfter, validUntil time.Time
	current, previous      [32]byte
}

// fixedEpochs anchors two fully live consensus epochs on either side of the
// 30-minute time-period boundary that precedes the run (rend-spec-v3
// [TIME-PERIODS] lattice; the signed hsdir_interval compresses the default
// 24-hour periods into 30-minute steps). Both epochs keep their validity
// windows open across the whole test, and the pair never straddles a UTC
// midnight, so period and SRV usage is deterministic on every run:
//
//	epoch A: first descriptor (TP k-1, SRV0), second (TP k, SRV1)
//	epoch B: first descriptor (TP k,   SRV1), second (TP k+1, SRV2)
//
// The epoch-B first descriptor carries over the epoch-A second descriptor
// without a directory or revision change; the new period's ring is what
// changes (rend-spec-v3 WHERE-HSDESC). Midnight is skipped: the exact
// 00:00 boundary is both an SRV and a period edge in this lattice, and C
// Tor's real 24-hour lattice never sees both edges at once.
func fixedEpochs() (a, b srvEpoch) {
	reference := time.Now().UTC().Truncate(time.Second)
	// TP k starts at Unix 43200+k*1800 minutes (12:00 UTC plus k 30-minute
	// steps). The last such boundary that leaves room after eA./eB before the
	// run clock g很好地 k*1800 <= reference−2min.
	k := (reference.Unix() - 43200 - 120) / 1800
	if k < 1 {
		k = 1
	}
	start := time.Unix(43200+k*1800, 0).UTC()
	// midnight edge to be skipped
	if start.Hour() == 0 && start.Minute() == 0 {
		start = start.Add(-30 * time.Minute)
	}
	for i := range 3 {
		srv := sha3.Sum256([]byte(fmt.Sprintf("gonion H3.1 srv %d", i)))
		switch i {
		case 0:
			a.previous = srv
		case 1:
			a.current, b.previous = srv, srv
		case 2:
			b.current = srv
		}
	}
	a.validAfter = start.Add(-time.Minute)
	a.validUntil = start.Add(2 * time.Hour)
	b.validAfter = start.Add(2 * time.Minute)
	b.validUntil = start.Add(2 * time.Hour)
	return a, b
}

func rolloverConsensus(t testing.TB, e srvEpoch, relaySeed [32]byte, hsdirs ...int) *common.Consensus {
	return testutil.ConsensusEpoch(t, testutil.EpochOptions{
		ValidAfter:    e.validAfter,
		ValidUntil:    e.validUntil,
		Current:       e.current,
		Previous:      e.previous,
		RelaySeed:     &relaySeed,
		HsdirInterval: 30,
		HSDirs:        hsdirs,
	})
}

// rolloverUpload is one captured HSDir upload keyed by blinded identity.
type rolloverUpload struct {
	period   descriptorPeriod
	blinded  [32]byte
	target   common.RouterStatus
	revision uint64
}

// durableRevisions mimics caller-owned persistence: reservations survive
// listener restarts and strictly increase per blinded identity. Every upload
// must carry the reservation in force when it was written, and a new batch
// never regresses below an earlier published revision.
type durableRevisions struct {
	t            testing.TB
	mu           sync.Mutex
	store        map[[32]byte]uint64 // durable reservation per blinded identity
	uploads      map[[32]byte]int
	reservations map[[32]byte]int
	published    map[[32]byte]uint64 // last uploaded revision per blinded identity
}

func newDurableRevisions(t testing.TB) *durableRevisions {
	return &durableRevisions{
		t:            t,
		store:        make(map[[32]byte]uint64),
		uploads:      make(map[[32]byte]int),
		reservations: make(map[[32]byte]int),
		published:    make(map[[32]byte]uint64),
	}
}

// NextRevision is the ServiceOptions.NextRevision contract: reserve and
// persist a strictly increasing revision before any upload attempt.
func (a *durableRevisions) NextRevision(_ context.Context, blinded [32]byte) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reserved := a.store[blinded] + 1
	a.store[blinded] = reserved
	a.reservations[blinded]++
	return reserved, nil
}

// captureUpload records one uploaded descriptor revision against the ledger.
func (a *durableRevisions) captureUpload(blinded [32]byte, revision uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if revision != a.store[blinded] {
		a.t.Errorf("uploaded revision %d does not match reserved %d for %x",
			revision, a.store[blinded], blinded[:4])
	}
	if a.published[blinded] > revision {
		a.t.Errorf("uploaded revision %d did not increase past %d for %x",
			revision, a.published[blinded], blinded[:4])
		return
	}
	// Uploads in one attempt share their reservation; later attempts carry a
	// strictly larger revision. Both extend the ledger without errors.
	a.published[blinded] = revision
	a.uploads[blinded]++
}

// snapshot copies the durable reservation state, for restart comparisons.
func (a *durableRevisions) snapshot() map[[32]byte]uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[[32]byte]uint64, len(a.store))
	maps.Copy(out, a.store)
	return out
}

// reservationCount returns the total number of reservations, across any
// listener, for per-period churn bounds.
func (a *durableRevisions) reservationCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	total := 0
	for _, n := range a.reservations {
		total += n
	}
	return total
}

// reservationLedger copies the per-blinded-identity reservation counts.
func (a *durableRevisions) reservationLedger() map[[32]byte]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[[32]byte]int, len(a.reservations))
	maps.Copy(out, a.reservations)
	return out
}

// rolloverFixture drives listener maintenance against mock relay circuits and
// signed test-network multis. Only descriptor publication and renewal are
// exercised; introduction failure and rendezvous flows are covered separately.
type rolloverFixture struct {
	t         *testing.T
	identity  ed25519.PrivateKey
	relaySeed [32]byte
	a, b      srvEpoch
	revisions *durableRevisions
	guards    *path.GuardManager

	mu          sync.Mutex
	uploads     []rolloverUpload
	peers       []net.Conn
	listeners   []*Listener
	blindedKeys map[[32]byte]descriptorPeriod // published blinded → source period
	circuits    []*lifecycleCircuit
	// introFailure rejects every introduction establishment; uploadStatus pins
	// an HTTP status per relay identity so a chosen replica upload fails.
	introFailure atomic.Bool
	uploadStatus map[[20]byte]int
	builds       atomic.Int32
}

func startRollover(t *testing.T) *rolloverFixture {
	t.Helper()
	f := &rolloverFixture{
		t:            t,
		identity:     ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)),
		relaySeed:    [32]byte(bytes.Repeat([]byte{0x5a}, 32)),
		revisions:    newDurableRevisions(t),
		blindedKeys:  make(map[[32]byte]descriptorPeriod),
		uploadStatus: make(map[[20]byte]int),
	}
	f.a, f.b = fixedEpochs()
	f.guards = guardfixture.Manager(t)
	t.Cleanup(func() {
		for _, l := range f.listeners {
			l.Close()
		}
		for _, peer := range f.peers {
			_ = peer.Close()
		}
		for _, circ := range f.circuits {
			circ.Close()
		}
	})
	return f
}

// newListener opens a fresh listener state over the same identity and durable
// revision store, mirroring a restart.
func (f *rolloverFixture) newListener() *Listener {
	f.t.Helper()
	l := &Listener{
		builder:       f.build(),
		opts:          ServiceOptions{Identity: bytes.Clone(f.identity), NextRevision: f.revisions.NextRevision},
		incoming:      make(chan net.Conn, 64),
		slots:         make(chan struct{}, 32),
		introCircuits: make(map[capi.Circ]struct{}),
		rendezvous:    make(map[capi.ServiceCirc]struct{}),
		descriptors:   make(map[descriptorPeriod]*serviceDescriptor),
		revisions:     make(map[[32]byte]uint64),
		retries:       make(map[descriptorPeriod]periodRetry),
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	f.listeners = append(f.listeners, l)
	return l
}

// blindFor computes and indexes the blinded public key for a period.
func (f *rolloverFixture) blindFor(p descriptorPeriod) *crypto.BlindedPublicKey {
	f.t.Helper()
	blinded, err := crypto.BlindPrivateKey(f.identity, p.number, p.length)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.blindedKeys[[32]byte(blinded.PublicKey().Bytes())] = p
	f.mu.Unlock()
	return blinded.PublicKey()
}

// build returns the guarded builder used by the renewal path; circuits work as
// both introduction relays (EstablishIntro ack) and directory upload peers.
func (f *rolloverFixture) build() guardedServiceBuild {
	return guardedServiceBuild{serviceBuildFunc: func(_ context.Context, relays []*common.RouterStatus) (capi.Circ, error) {
		f.builds.Add(1)
		conn, peer := net.Pipe()
		life, closeCirc := context.WithCancel(context.Background())
		circ := &epochCircuit{lifecycleCircuit: &lifecycleCircuit{ctx: life, cancel: closeCirc}, f: f, target: *relays[len(relays)-1], conn: conn}
		f.mu.Lock()
		f.peers = append(f.peers, peer)
		f.mu.Unlock()
		go f.serveDescriptorUploads(circ, peer)
		return circ, nil
	}, guards: f.guards}
}

// epochCircuit satisfies both the ServiceCirc introduction path and the
// directory publication stream of a mock relay.
type epochCircuit struct {
	*lifecycleCircuit
	f         *rolloverFixture
	target    common.RouterStatus
	control   chan relay.Cell
	conn      net.Conn
	establish sync.Once
}

func (c *epochCircuit) HopCount() int { return 3 }
func (c *epochCircuit) NewStream(target string, hop int) (capi.Stream, error) {
	if target != "dir" || hop != 2 {
		return nil, fmt.Errorf("unexpected directory stream target")
	}
	return &publicationStream{conn: c.conn}, nil
}
func (c *epochCircuit) SetHSControl(ch chan relay.Cell) { c.control = ch }
func (c *epochCircuit) EstablishIntro(ed25519.PrivateKey) error {
	if c.f.introFailure.Load() {
		return errors.New("introduction relay unavailable")
	}
	if c.control == nil {
		return nil
	}
	ack := func() {
		c.control <- &relay.IntroEstablishedCell{}
	}
	c.establish.Do(ack)
	return nil
}
func (c *epochCircuit) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	select {
	case cell := <-c.control:
		return cell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (c *epochCircuit) AcceptStream(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *epochCircuit) StopAccepting() error { return nil }
func (c *epochCircuit) JoinRendezvous([20]byte, []byte, []byte, []byte, []byte, []byte, string) error {
	return nil
}
func (c *epochCircuit) AppendE2EHop([]byte, []byte, []byte, []byte) error { return nil }

// serveDescriptorUploads handles one descriptor POST over the pipe peer and
// closes the peer so the request returns.
func (f *rolloverFixture) serveDescriptorUploads(c *epochCircuit, peer net.Conn) {
	defer peer.Close()
	_ = c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(30 * time.Second))
	f.mu.Lock()
	status, pinned := f.uploadStatus[c.target.NodeID]
	f.mu.Unlock()
	if !pinned {
		status = 200
	}
	for {
		req, err := http.ReadRequest(bufio.NewReader(peer))
		if err != nil {
			return
		}
		if req.Method != http.MethodPost || req.URL.Path != "/tor/hs/3/publish" {
			f.t.Errorf("unexpected directory request %s %s", req.Method, req.URL.Path)
			return
		}
		raw, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			f.t.Error(err)
			return
		}
		if status == 200 {
			f.recordUpload(raw, c)
		}
		if _, err := fmt.Fprintf(peer, "HTTP/1.0 %d result\r\nContent-Length: 0\r\n\r\n", status); err != nil {
			f.t.Error(err)
			return
		}
	}
}

// recordUpload verifies and stores one descriptor upload before the response
// releases the publish worker.
func (f *rolloverFixture) recordUpload(raw []byte, c *epochCircuit) {
	parsed, err := desc.Parse(raw)
	if err != nil {
		f.t.Error(err)
		return
	}
	f.mu.Lock()
	period, indexed := f.blindedKeys[[32]byte(parsed.BlindedKey)]
	f.mu.Unlock()
	if !indexed {
		f.t.Errorf("upload for untracked blinded identity %x", parsed.BlindedKey[:4])
		return
	}
	blinded := [32]byte(parsed.BlindedKey)
	f.revisions.captureUpload(blinded, parsed.RevisionCounter)
	f.mu.Lock()
	f.uploads = append(f.uploads, rolloverUpload{
		period:   period,
		blinded:  blinded,
		target:   c.target,
		revision: parsed.RevisionCounter,
	})
	f.mu.Unlock()
}

// uploadsAfter returns uploads captured beyond the first n entries.
func (f *rolloverFixture) uploadsAfter(n int) []rolloverUpload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.uploads[n:])
}

// uploadsCount returns the captured upload length.
func (f *rolloverFixture) uploadsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

// renewOnce drives one maintenance renewal against an epoch and fails the
// test on any renewal error.
func (f *rolloverFixture) renewOnce(t *testing.T, l *Listener, cns *common.Consensus) {
	t.Helper()
	l.consensus = func() *common.Consensus { return cns }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := l.renew(ctx); err != nil {
		t.Fatalf("renew with %s consensus failed: %v", cns.ValidAfter.Format(time.RFC3339), err)
	}
}

// assertUploads checks that every captured upload belongs to a tracked period,
// that each descriptor went to exactly the responsible HSDir ring of its
// descriptor segment (descriptor index 0 uses the previous SRV, index 1 the
// current SRV), that revisions strictly increase per blinded identity, and
// that each published blinded identity matches the period key.
func (f *rolloverFixture) assertUploads(t *testing.T, cns *common.Consensus, uploads []rolloverUpload, second map[[32]byte]bool) {
	t.Helper()
	byBlinded := make(map[[32]byte][]rolloverUpload)
	for _, u := range uploads {
		if _, tracked := f.blindedKeys[u.blinded]; !tracked {
			t.Fatalf("upload for untracked blinded identity %x", u.blinded[:4])
		}
		byBlinded[u.blinded] = append(byBlinded[u.blinded], u)
	}
	for blinded, ups := range byBlinded {
		p := f.blindedKeys[blinded]
		blindedKey, err := crypto.BlindPrivateKey(f.identity, p.number, p.length)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(blindedKey.PublicKey().Bytes(), blinded[:]) {
			t.Fatalf("published blind %x is not the period key of %+v", blinded[:4], p)
		}
		if len(ups) < 2 {
			t.Fatalf("period %+v published to %d HSDirs", p, len(ups))
		}
		isSecond := second[blinded]
		srv := sharedRandom(cns, p.number, p.length, isSecond)
		groups, err := hsdirReplicas(cns, blindedKey.PublicKey(), p.number, p.length, srv, true)
		if err != nil {
			t.Fatal(err)
		}
		want := make(map[[20]byte]bool)
		wantList := make([]string, 0, 8)
		for _, group := range groups {
			for _, r := range group {
				if _, dupe := want[r.NodeID]; dupe {
					continue
				}
				want[r.NodeID] = true
				wantList = append(wantList, fmt.Sprint(r.NodeID[0]))
			}
		}
		got := make(map[[20]byte]bool)
		gotList := make([]string, 0, len(ups))
		for _, u := range ups {
			got[u.target.NodeID] = true
			gotList = append(gotList, fmt.Sprint(u.target.NodeID[0]))
		}
		if len(gotList) != len(wantList) {
			t.Fatalf("period %+v uploaded to %v, want ring %v", p, gotList, wantList)
		}
		for node := range got {
			if !want[node] {
				t.Errorf("period %+v uploaded to relay %d outside its ring", p, node[0])
			}
		}
		for node := range want {
			if !got[node] {
				t.Errorf("period %+v uploaded %d left a responsible HSDir out", p, node[0])
			}
		}
	}
}

// uploadsOf groups uploads by blinded identity.
func uploadsOf(uploads []rolloverUpload) map[[32]byte][]rolloverUpload {
	out := make(map[[32]byte][]rolloverUpload)
	for _, u := range uploads {
		out[u.blinded] = append(out[u.blinded], u)
	}
	return out
}

func TestServiceRolloverAcrossEpochs(t *testing.T) {
	f := startRollover(t)
	cnsA := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	cnsB := rolloverConsensus(t, f.b, f.relaySeed, 0, 1, 2, 3, 4, 5)
	periodsA, periodsB := servicePeriods(cnsA), servicePeriods(cnsB)
	// The epoch-B first descriptor carries over the epoch-A second descriptor;
	// only the SRV label (current/previous) flips at the midnight boundary.
	if periodsA[1] != periodsB[0] || periodsB[1].number != periodsB[0].number+1 {
		t.Fatalf("epoch periods misaligned: A %+v, B %+v", periodsA, periodsB)
	}
	blindRetainedA, err := crypto.BlindPrivateKey(f.identity, periodsA[1].number, periodsA[1].length)
	if err != nil {
		t.Fatal(err)
	}
	blindRetainedB, err := crypto.BlindPrivateKey(f.identity, periodsB[0].number, periodsB[0].length)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blindRetainedA.PublicKey().Bytes(), blindRetainedB.PublicKey().Bytes()) {
		t.Fatal("blinded identity changed although the time period did not")
	}

	blindOld := [32]byte(f.blindFor(periodsA[0]).Bytes())
	blindRetained := [32]byte(f.blindFor(periodsA[1]).Bytes())
	blindNew := [32]byte(f.blindFor(periodsB[1]).Bytes())

	l := f.newListener()
	// Epoch A publishes both overlapping descriptors (FIRST/SECOND DESCUPLOAD).
	f.renewOnce(t, l, cnsA)
	f.assertUploads(t, cnsA, f.uploadsAfter(0), map[[32]byte]bool{blindOld: false, blindRetained: true})
	// The retained period's descriptor object is the one that must survive the
	// rollover without rebuilding its introductions.
	retainedDescriptor := l.descriptors[periodsA[1]]
	count := f.uploadsCount()

	// Epoch B rotates to {retained period, new period}: the retained descriptor
	// keeps its introduction points and its (TP, SRV) responsible ring, and is
	// republished on WHEN-HSDESC cadence with a strictly larger revision; the
	// new period is built and published from scratch.
	f.renewOnce(t, l, cnsB)
	newUploads := uploadsOf(f.uploadsAfter(count))
	if len(newUploads) != 1 {
		t.Fatalf("epoch B uploaded %d blinded identities, want only the new period", len(newUploads))
	}
	f.assertUploads(t, cnsB, f.uploadsAfter(count), map[[32]byte]bool{blindNew: true})
	if l.descriptors[periodsB[0]] != retainedDescriptor {
		t.Fatal("the retained period rebuilt introductions instead of rotating")
	}

	// The preceding period now lives in the retiring set with three hours of
	// publication promise; its introductions must stay open until then.
	if _, active := l.descriptors[periodsA[0]]; active {
		t.Fatal("retired period stayed active")
	}
	var retired *serviceDescriptor
	for _, d := range l.retired {
		if d.period == periodsA[0] {
			retired = d
		}
	}
	if retired == nil {
		t.Fatal("the previous period was not retained as retired")
	}
	for _, ip := range retired.intros {
		if ip.circuit.Ctx().Err() != nil {
			t.Fatal("retired introductions were closed before their lifetime")
		}
	}
	l.pruneRetired(retired.published.Add(3 * time.Hour))
	for _, ip := range retired.intros {
		if ip.circuit.Ctx().Err() == nil {
			t.Fatal("expired introductions were not closed at three hours")
		}
	}
	// Revision bookkeeping is bounded to the two live blinded identities; the
	// pruned identity cannot roll any counter forward.
	if len(l.revisions) != 2 {
		t.Fatalf("revision history kept %d entries, want the two live blinded identities", len(l.revisions))
	}
	for key := range l.revisions {
		if key != blindRetained && key != blindNew {
			t.Errorf("revision history kept a retired blinded identity %x", key[:4])
		}
	}
	// Two managed periods, both with fully established introductions.
	for key, d := range l.descriptors {
		if key != periodsB[0] && key != periodsB[1] {
			t.Fatalf("unexpected active period %+v", key)
		}
		if len(d.intros) != 3 {
			t.Fatalf("period %+v retained %d introductions", key, len(d.intros))
		}
	}
	if len(l.retries) != 0 {
		t.Fatalf("successful maintenance left retry pacing: %+v", l.retries)
	}
}

func TestServiceRolloverChangedHSDirs(t *testing.T) {
	// A consensus change drops an HSDir: the responsible ring for every live
	// period shrinks. Renewal must republish both descriptors immediately,
	// reserving fresh revisions for the same blinded identities, and leave no
	// retry pacing behind (rend-spec-v3 WHERE-HSDESC).
	f := startRollover(t)
	full := rolloverConsensus(t, f.b, f.relaySeed, 0, 1, 2, 3, 4, 5)
	reduced := rolloverConsensus(t, f.b, f.relaySeed, 0, 1, 2, 3, 4)
	periods := servicePeriods(full)
	blindFirst := [32]byte(f.blindFor(periods[0]).Bytes())
	blindSecond := [32]byte(f.blindFor(periods[1]).Bytes())
	want := map[[32]byte]bool{blindFirst: false, blindSecond: true}

	l := f.newListener()
	f.renewOnce(t, l, full)
	before := uploadsOf(f.uploadsAfter(0))
	f.assertUploads(t, full, f.uploadsAfter(0), want)
	count := f.uploadsCount()

	f.renewOnce(t, l, reduced)
	after := uploadsOf(f.uploadsAfter(count))
	f.assertUploads(t, reduced, f.uploadsAfter(count), want)
	for blinded, ups := range after {
		if len(ups) >= len(before[blinded]) {
			t.Errorf("reduced ring still published to %d HSDirs, before %d", len(ups), len(before[blinded]))
		}
	}
	if len(l.retries) != 0 {
		t.Fatalf("material directory change did not clear retry pacing: %+v", l.retries)
	}
}

func TestServiceDelayedClientFetch(t *testing.T) {
	// A delayed client holds its epoch-A consensus after the service already
	// rolled over: CLIENTFETCH derives (TP k, SRV1) from the stale consensus,
	// exactly the pairing the service retained as its epoch-B first descriptor,
	// so every fetch directory received that descriptor at publication time.
	f := startRollover(t)
	cnsA := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	cnsB := rolloverConsensus(t, f.b, f.relaySeed, 0, 1, 2, 3, 4, 5)
	periodsA := servicePeriods(cnsA)
	clientPeriod := cnsA.CalcPeriodNum()
	if clientPeriod != periodsA[1].number {
		t.Fatalf("delayed client period %d, service second descriptor covers %d", clientPeriod, periodsA[1].number)
	}
	p := periodsA[1]
	srv := clientSRV(cnsA, p.number, p.length)
	if srv != sharedRandom(cnsA, p.number, p.length, true) {
		t.Fatal("delayed client SRV does not match the retained descriptor pairing")
	}
	if srv != sharedRandom(cnsB, p.number, p.length, false) {
		t.Fatal("the retained pairing changed across the epoch rollover")
	}
	blinded, err := crypto.BlindPrivateKey(f.identity, p.number, p.length)
	if err != nil {
		t.Fatal(err)
	}
	clientRing, err := hsdirReplicas(cnsA, blinded.PublicKey(), p.number, p.length, srv, false)
	if err != nil {
		t.Fatal(err)
	}
	storeRing, err := hsdirReplicas(cnsB, blinded.PublicKey(), p.number, p.length, sharedRandom(cnsB, p.number, p.length, false), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientRing) != len(storeRing) {
		t.Fatalf("%d client replicas against %d store replicas", len(clientRing), len(storeRing))
	}
	// Every responsible fetch relay must be inside the union the service
	// published to: a delayed client reaches the descriptor no matter which
	// replica group its stale consensus lands in.
	for _, group := range clientRing {
		for _, r := range group {
			for _, store := range storeRing {
				if slices.ContainsFunc(store, func(s common.RouterStatus) bool { return s.NodeID == r.NodeID }) {
					break
				}
			}
		}
	}
	for i, group := range clientRing {
		for _, r := range group {
			inStore := false
			for _, store := range storeRing {
				if slices.ContainsFunc(store, func(s common.RouterStatus) bool { return s.NodeID == r.NodeID }) {
					inStore = true
					break
				}
			}
			if !inStore {
				t.Errorf("client replica %d fetches relay %d which was never published to", i+1, r.NodeID[0])
			}
		}
	}
	// Each fetch replica holds the consensus spread (hsdir_spread_fetch).
	for i, group := range clientRing {
		if len(group) != 3 {
			t.Errorf("client replica %d fetch spread %d, want 3", i+1, len(group))
		}
	}
}

func TestServiceRestartReservesNextRevision(t *testing.T) {
	// A restart inherits nothing but the identity: every publication reserves
	// the next durable revision, so a restarted listener cannot reuse a
	// previously reserved counter. The reserved numbers survive the exchange
	// as caller-owned state.
	f := startRollover(t)
	cns := rolloverConsensus(t, f.b, f.relaySeed, 0, 1, 2, 3, 4, 5)
	periods := servicePeriods(cns)
	f.blindFor(periods[0])
	f.blindFor(periods[1])
	first := f.newListener()
	f.renewOnce(t, first, cns)
	reservedBefore := f.revisions.snapshot()

	restart := f.newListener()
	f.renewOnce(t, restart, cns)
	reservedAfter := f.revisions.snapshot()
	for blinded, latest := range reservedAfter {
		before, ok := reservedBefore[blinded]
		if !ok || latest != before+1 {
			t.Errorf("restart used revision %d, expected %d for blinded %x", latest, before+1, blinded[:4])
		}
	}
	if len(reservedAfter) != 2 {
		t.Fatalf("published %d blinded identities per epoch", len(reservedAfter))
	}
	if len(restart.revisions) != 2 || len(first.revisions) != 2 {
		t.Fatalf("in-process revision history did not stay bounded: restart %d, first %d", len(restart.revisions), len(first.revisions))
	}
}

// transferRendezvous mirrors a live rendezvous circuit whose teardown closes
// already-accepted streams, as Shutdown promises.
type transferRendezvous struct {
	*lifecycleCircuit
	sync.Mutex
	streams  chan net.Conn
	accepted []net.Conn
}

func (c *transferRendezvous) AcceptStream(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-c.streams:
		c.Lock()
		c.accepted = append(c.accepted, conn)
		c.Unlock()
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *transferRendezvous) Close() error {
	c.cancel()
	c.Lock()
	defer c.Unlock()
	for _, conn := range c.accepted {
		_ = conn.Close()
	}
	return nil
}
func (c *transferRendezvous) StopAccepting() error                              { return nil }
func (c *transferRendezvous) AppendE2EHop([]byte, []byte, []byte, []byte) error { return nil }
func (c *transferRendezvous) JoinRendezvous([20]byte, []byte, []byte, []byte, []byte, []byte, string) error {
	return nil
}
func (c *transferRendezvous) NewStream(string, int) (capi.Stream, error) {
	return nil, fmt.Errorf("unexpected stream")
}
func (c *transferRendezvous) SendHSControl(relay.Cell) error { return nil }
func (c *transferRendezvous) HopCount() int                  { return 3 }
func (c *transferRendezvous) Ctx() context.Context           { return c.lifecycleCircuit.Ctx() }

// TestServiceAcceptedTransferUnderRotation drives a listener through the
// epoch-B renewal while an accepted stream keeps pumping bytes over its
// rendezvous circuit. Rotation may retire introductions, but the accepted
// stream and rendezvous circuit survive Close; only Shutdown terminates them.
func TestServiceAcceptedTransferUnderRotation(t *testing.T) {
	f := startRollover(t)
	cnsA := rolloverConsensus(t, f.a, f.relaySeed, 0, 1, 2, 3, 4, 5)
	cnsB := rolloverConsensus(t, f.b, f.relaySeed, 0, 1, 2, 3, 4, 5)
	for _, p := range servicePeriods(cnsA) {
		f.blindFor(p)
	}
	for _, p := range servicePeriods(cnsB) {
		f.blindFor(p)
	}
	l := f.newListener()
	f.renewOnce(t, l, cnsA)

	// A manually registered rendezvous circuit pumps accepted streams
	// independently of descriptor maintenance.
	circCtx, circCloseCirc := context.WithCancel(context.Background())
	defer circCloseCirc()
	circ := &transferRendezvous{lifecycleCircuit: &lifecycleCircuit{ctx: circCtx, cancel: circCloseCirc}, streams: make(chan net.Conn, 4)}
	l.mu.Lock()
	l.rendezvous[circ] = struct{}{}
	l.mu.Unlock()
	go l.acceptRendezvous(circ)

	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	circ.streams <- conn
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	exchange := func(t *testing.T) {
		t.Helper()
		msg := "transfer under rotation"
		_ = peer.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
		done := make(chan error, 1)
		go func() {
			_, err := peer.Write([]byte(msg))
			done <- err
		}()
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(accepted, buf); err != nil || !bytes.Equal(buf, []byte(msg)) {
			t.Fatalf("transfer: %q %v", buf, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	exchange(t)

	// Rotate the descriptors: only period bookkeeping and introductions
	// change; the accepted stream flows on.
	f.renewOnce(t, l, cnsB)
	exchange(t)

	// Close preserves accepted connections; Accept stops.
	l.Close()
	exchange(t)
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("Accept after Close accepted")
	}

	// Shutdown terminates the accepted stream and the rendezvous circuit: the
	// accepted pipe end is closed, so both pipe observers fail.
	l.Shutdown()
	_ = peer.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, writeErr := peer.Write([]byte("after"))
	buf := make([]byte, 5)
	_ = accepted.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := accepted.Read(buf)
	if writeErr == nil && readErr == nil {
		t.Fatal("accepted stream survived Shutdown")
	}
}

// TestServiceRendezvousSlotSaturationAndRelease pins the 32-slot rendezvous
// ceiling: saturated request budget drops introduction cells without
// starting a join, a free slot serves exactly one request, and a failed join
// releases its slot for later work.
func TestServiceRendezvousSlotSaturationAndRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Listener{
		ctx:           ctx,
		cancel:        cancel,
		opts:          ServiceOptions{Identity: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))},
		introCircuits: make(map[capi.Circ]struct{}),
		rendezvous:    make(map[capi.ServiceCirc]struct{}),
	}
	l.slots = make(chan struct{}, 32)
	for range 32 {
		l.slots <- struct{}{}
	}

	// One valid introduction request against the saturated budget: the
	// request is dropped and no rendezvous circuit is started.
	ip := saturationIntro(t)
	feed := make(chan relay.Cell, 4)
	circuitCtx, circuitClose := context.WithCancel(context.Background())
	defer circuitClose()
	ip.circuit = &fedIntroCircuit{lifecycleCircuit: &lifecycleCircuit{ctx: circuitCtx, cancel: circuitClose}, feed: feed}
	dropped := make(chan struct{}, 1)
	go func() {
		l.receiveIntroductions(ip)
		close(dropped)
	}()
	feed <- saturationCell(t, ip)
	if !waitUntil(2*time.Second, func() bool { return len(l.rendezvous) == 0 && len(l.slots) == 32 }) {
		t.Fatalf("a saturated budget reserved state: slots=%d rendezvous=%d", len(l.slots), len(l.rendezvous))
	}

	// Freeing one slot serves exactly one request; the failed join releases
	// its slot for later work, leaving the budget one slot lighter.
	<-l.slots
	feed <- saturationCell(t, ip)
	if !waitUntil(2*time.Second, func() bool { return len(l.slots) == 31 && len(l.rendezvous) == 0 }) {
		t.Fatalf("the join did not release its slot: slots=%d rendezvous=%d", len(l.slots), len(l.rendezvous))
	}
	// An unknown cell type also terminates the receive loop.
	feed <- &relay.RendezvousEstablishedCell{}
	select {
	case <-dropped:
	case <-time.After(2 * time.Second):
		t.Fatal("the receive loop did not stop on unmanaged traffic")
	}
	l.Close()
}

// saturationIntro builds a real introduction point state for the rendezvous
// saturation fixtures.
func saturationIntro(t *testing.T) *serviceIntroduction {
	t.Helper()
	keySeed := serviceHex(t, "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	ipKey, err := ecdh.X25519().NewPrivateKey(keySeed)
	if err != nil {
		t.Fatal(err)
	}
	auth := serviceHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	sub := serviceHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	return &serviceIntroduction{key: ipKey, subcredential: sub, descriptor: desc.IntroPoint{AuthKey: auth}}
}

// saturationCell encrypts a fresh introduction request with a distinct
// rendezvous cookie, as a client would deliver石刻 it.
func saturationCell(t *testing.T, ip *serviceIntroduction) *relay.Introduce2Cell {
	t.Helper()
	plain := serviceHex(t, introducePlaintextVector)
	plain = append(append(bytes.Clone(plain[:20]), 0), plain[23:]...)
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	copy(plain, random)
	clientSeed := serviceHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	client, err := ecdh.X25519().NewPrivateKey(clientSeed)
	if err != nil {
		t.Fatal(err)
	}
	_, blob, err := crypto.HsClientIntro(client, ip.key.PublicKey(), ip.descriptor.AuthKey, ip.subcredential, plain)
	if err != nil {
		t.Fatal(err)
	}
	cell := &relay.Introduce2Cell{Payload: blob}
	cell.AuthKey = bytes.Clone(ip.descriptor.AuthKey)
	return cell
}

// fedIntroCircuit replays controlled introduction cells onto the receive loop.
type fedIntroCircuit struct {
	*lifecycleCircuit
	feed chan relay.Cell
}

func (c *fedIntroCircuit) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	select {
	case cell := <-c.feed:
		return cell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}
