package hs

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
)

func serviceHex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Tor/Chutney capture published in rend-spec-v3 Appendix G.1, including
// the encrypted extension and trailing padding. Expectations are not generated
// by Gonion's serializer.
const introducePlaintextVector = `
6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCA
C4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F0000
0113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B
7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF870000000000
0000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000`

func TestServiceIntroductionPlaintextVector(t *testing.T) {
	plain := serviceHex(t, introducePlaintextVector)
	r, err := parseIntroductionPlaintext(plain)
	if err != nil {
		t.Fatal(err)
	}
	if r.cookie != [20]byte(serviceHex(t, "6BD364C12638DD5C3BE23D76ACA05B04E6CE932C")) || r.target.Ipv4Addr != "127.0.0.1" || r.target.ORPort != 5001 || !r.congestionControl {
		t.Fatalf("wrong capture fields: %+v", r)
	}
	want := serviceHex(t, "0300067F00000113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF87")
	if !bytes.Equal(r.target.LinkSpecifiers, want) {
		t.Fatalf("link specifiers changed or include PAD: %x", r.target.LinkSpecifiers)
	}
	if !bytes.Equal(r.target.NTorOnionKey.Bytes(), serviceHex(t, "0DE6130E4FCAC4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE56545")) {
		t.Fatal("wrong rendezvous onion key")
	}
	// Unknown specifiers must survive in exactly their original order.
	prefix := bytes.Clone(plain[:59])
	prefix[58] = 4
	withUnknown := append(prefix, 99, 2, 9, 8)
	withUnknown = append(withUnknown, want[1:]...)
	r, err = parseIntroductionPlaintext(withUnknown)
	if err != nil || !bytes.Equal(r.target.LinkSpecifiers, withUnknown[58:]) {
		t.Fatalf("unknown specifier forwarding: %v", err)
	}
	// Every truncation before the end of NSPEC must fail, not panic.
	end := 58 + len(want)
	for n := 0; n < end; n++ {
		if _, err := parseIntroductionPlaintext(plain[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, offset := range []int{23, 24, 25, 60, 68, 90} {
		bad := bytes.Clone(plain)
		bad[offset] = 255
		if _, err := parseIntroductionPlaintext(bad); err == nil {
			t.Fatalf("accepted malformed key/specifier at %d", offset)
		}
	}
	bad := bytes.Clone(plain)
	clear(bad[26:58])
	if _, err := parseIntroductionPlaintext(bad); err == nil {
		t.Fatal("accepted low-order ntor key")
	}
}

func TestServiceIntroductionAuthenticationAndReplay(t *testing.T) {
	b, _ := ecdh.X25519().NewPrivateKey(serviceHex(t, "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A"))
	x, _ := ecdh.X25519().NewPrivateKey(serviceHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341"))
	auth := serviceHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	sub := serviceHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	ip := &serviceIntroduction{key: b, subcredential: sub, descriptor: desc.IntroPoint{AuthKey: auth}}
	plain := serviceHex(t, introducePlaintextVector)
	// Remove the captured extension: our descriptor does not advertise CC.
	plain = append(append(bytes.Clone(plain[:20]), 0), plain[23:]...)
	makeCell := func(plain []byte) *relay.Introduce2Cell {
		t.Helper()
		_, blob, err := crypto.HsClientIntro(x, b.PublicKey(), auth, sub, plain)
		if err != nil {
			t.Fatal(err)
		}
		c := &relay.Introduce2Cell{Payload: blob}
		c.AuthKey = bytes.Clone(auth)
		return c
	}
	cell := makeCell(plain)
	r, err := ip.decrypt(cell)
	if err != nil || !r.clientKey.Equal(x.PublicKey()) {
		t.Fatalf("valid introduction: %v", err)
	}
	if _, err := ip.decrypt(cell); !errors.Is(err, errIntroductionReplay) {
		t.Fatalf("full-cell replay: %v", err)
	}
	// Changing authenticated PAD produces new ciphertext but the same cookie.
	plain[len(plain)-1] = 1
	if _, err := ip.decrypt(makeCell(plain)); !errors.Is(err, errIntroductionReplay) {
		t.Fatalf("cookie replay: %v", err)
	}
	cell = makeCell(plain)
	cell.AuthKey[0] ^= 1
	if _, err := ip.decrypt(cell); err == nil {
		t.Fatal("wrong auth key accepted")
	}
	cell = makeCell(plain)
	cell.Exts = []relay.Ext{{Type: 99}}
	if _, err := ip.decrypt(cell); err == nil {
		t.Fatal("unauthenticated outer extension accepted")
	}
	for len(ip.cells) < maxIntroductionReplays {
		var digest [32]byte
		n := len(ip.cells)
		digest[0], digest[1] = byte(n), byte(n>>8)
		ip.cells[digest] = struct{}{}
	}
	plain[0] ^= 1
	if _, err := ip.decrypt(makeCell(plain)); !errors.Is(err, errReplayCacheFull) {
		t.Fatalf("replay-cache limit: %v", err)
	}
}

func TestServicePeriods(t *testing.T) {
	// FIRSTDESCUPLOAD / SECONDDESCUPLOAD: descriptors rotate at SRV midnight,
	// not at TP noon. Include both adjacent periods throughout the day.
	var previous [2]descriptorPeriod
	for _, hour := range []int{1, 11, 12, 13, 23} {
		at := time.Date(2016, 4, 13, hour, 0, 0, 0, time.UTC)
		c := &common.Consensus{ValidAfter: at, FreshUntil: at.Add(time.Hour)}
		p := servicePeriods(c)
		if p[0].number != 16903 || p[1].number != 16904 || p[0].length != 1440 {
			t.Fatalf("hour %d: %+v", hour, p)
		}
		if hour != 1 && p != previous {
			t.Fatal("rotated descriptors at noon instead of midnight")
		}
		previous = p
	}
}

func TestServiceRevisionReservationFailure(t *testing.T) {
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	key, err := crypto.BlindPrivateKey(identity, 16903, 1440)
	if err != nil {
		t.Fatal(err)
	}
	storageErr := errors.New("revision storage unavailable")
	l := &Listener{opts: ServiceOptions{NextRevision: func(context.Context, [32]byte) (uint64, error) { return 0, storageErr }}, revisions: make(map[[32]byte]uint64)}
	d := &serviceDescriptor{blinded: key}
	if err := l.publish(context.Background(), nil, d, nil); !errors.Is(err, storageErr) {
		t.Fatalf("did not fail before encoding/network: %v", err)
	}
	l.opts.NextRevision = func(context.Context, [32]byte) (uint64, error) { return 42, nil }
	l.revisions[[32]byte(key.PublicKey().Bytes())] = 42
	if err := l.publish(context.Background(), nil, d, nil); err == nil || !strings.Contains(err.Error(), "did not increase") {
		t.Fatalf("revision reuse accepted: %v", err)
	}
	l.opts = ServiceOptions{Identity: identity, Port: 80, NextRevision: l.opts.NextRevision}
	if err := l.opts.Validate(); err != nil {
		t.Fatal(err)
	}
	l.opts.Identity = bytes.Clone(identity)
	l.opts.Identity[63] ^= 1
	if err := l.opts.Validate(); err == nil {
		t.Fatal("inconsistent identity accepted")
	}
}

type lifecycleCircuit struct {
	capi.ServiceCirc
	ctx     context.Context
	cancel  context.CancelFunc
	stopped atomic.Bool
}

func (c *lifecycleCircuit) Close() error         { c.cancel(); return nil }
func (c *lifecycleCircuit) StopAccepting() error { c.stopped.Store(true); return nil }
func (c *lifecycleCircuit) Ctx() context.Context { return c.ctx }

func TestListenerClosePreservesAcceptedConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	circCtx, closeCirc := context.WithCancel(context.Background())
	defer closeCirc()
	rp := &lifecycleCircuit{ctx: circCtx, cancel: closeCirc}
	l := &Listener{ctx: ctx, cancel: cancel, incoming: make(chan net.Conn, 2), rendezvous: map[capi.ServiceCirc]struct{}{rp: {}}}
	accepted, peer := net.Pipe()
	defer accepted.Close()
	defer peer.Close()
	pending, pendingPeer := net.Pipe()
	defer pendingPeer.Close()
	l.incoming <- accepted
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	l.incoming <- pending
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if !rp.stopped.Load() || circCtx.Err() != nil {
		t.Fatal("Close killed accepted circuit or did not stop acceptance")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte{42}); done <- err }()
	if n, err := conn.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("accepted stream closed: %d %v", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := pendingPeer.Write([]byte{1}); err == nil {
		t.Fatal("pending connection survived Close")
	}
	_ = l.Shutdown()
	if circCtx.Err() == nil {
		t.Fatal("Shutdown left rendezvous open")
	}
}

type serviceBuildFunc func(context.Context, []*common.RouterStatus) (capi.Circ, error)

func (f serviceBuildFunc) BuildPath(_ uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	return f(context.Background(), relays)
}
func (f serviceBuildFunc) BuildPathContext(ctx context.Context, _ uint32, relays []*common.RouterStatus) (capi.Circ, error) {
	return f(ctx, relays)
}

type introTestCircuit struct {
	*lifecycleCircuit
	control chan relay.Cell
	fail    bool
}

func (c *introTestCircuit) SetHSControl(ch chan relay.Cell) { c.control = ch }
func (c *introTestCircuit) EstablishIntro(ed25519.PrivateKey) error {
	if c.fail {
		return errors.New("introduction relay unavailable")
	}
	c.control <- &relay.IntroEstablishedCell{}
	return nil
}
func (c *introTestCircuit) RecvHSControl(ctx context.Context) (relay.Cell, error) {
	select {
	case cell := <-c.control:
		return cell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}

func TestServiceReplacesUnavailableIntroduction(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l := &Listener{ctx: ctx, cancel: cancel, opts: ServiceOptions{Identity: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))}, introCircuits: make(map[capi.Circ]struct{})}
	defer l.Close()
	seen := make(map[[20]byte]bool)
	var circuits []*introTestCircuit
	l.builder = serviceBuildFunc(func(_ context.Context, relays []*common.RouterStatus) (capi.Circ, error) {
		target := relays[len(relays)-1].NodeID
		if seen[target] {
			t.Error("reused failed or already established intro target")
		}
		seen[target] = true
		life, closeCirc := context.WithCancel(context.Background())
		circ := &introTestCircuit{lifecycleCircuit: &lifecycleCircuit{ctx: life, cancel: closeCirc}, fail: len(circuits) == 0}
		circuits = append(circuits, circ)
		return circ, nil
	})
	// The signed test network has the same key/descriptor layout as the
	// Tor/Chutney fixture. Only the circuit I/O is simulated here.
	d, err := l.newDescriptor(ctx, cns, descriptorPeriod{cns.CalcPeriodNum(), cns.CalcPeriodLength()})
	if err != nil {
		t.Fatal(err)
	}
	defer l.retire(d)
	if len(d.intros) != 3 || len(circuits) != 4 || circuits[0].Ctx().Err() == nil {
		t.Fatal("unavailable intro was not replaced and closed")
	}
	for _, ip := range d.intros {
		if ip.circuit.Ctx().Err() != nil {
			t.Fatal("successful intro did not outlive establishment context")
		}
	}
}

func TestServicePublicationBoundsAndCancellation(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	blinded, err := crypto.BlindPrivateKey(identity, cns.CalcPeriodNum(), cns.CalcPeriodLength())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var active, maximum, reserved atomic.Int32
	started := make(chan struct{}, 8)
	l := &Listener{revisions: make(map[[32]byte]uint64)}
	l.opts.NextRevision = func(context.Context, [32]byte) (uint64, error) { reserved.Add(1); return 1, nil }
	l.builder = serviceBuildFunc(func(ctx context.Context, _ []*common.RouterStatus) (capi.Circ, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, n) {
				break
			}
		}
		if reserved.Load() != 1 {
			t.Error("network operation preceded revision reservation")
		}
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	d := &serviceDescriptor{blinded: blinded, signing: identity}
	groups := [][]common.RouterStatus{cns.RelayInformation[:3], cns.RelayInformation[3:]}
	done := make(chan error, 1)
	go func() { done <- l.publish(ctx, cns, d, groups) }()
	for range 4 {
		select {
		case <-started:
		case err := <-done:
			t.Fatalf("publication exited before launching four workers: %v", err)
		case <-ctx.Done():
			t.Fatal("publication serialized blocked uploads")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || active.Load() != 0 || maximum.Load() != 4 || !d.nextPublication.IsZero() {
			t.Fatalf("publication cancellation/bounds: %v, active=%d max=%d", err, active.Load(), maximum.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publication workers ignored cancellation")
	}
}

func TestServiceCookieReplayAcrossIntroKeys(t *testing.T) {
	l := &Listener{ctx: context.Background()}
	now := time.Now()
	cookie := [20]byte{42}
	if !l.claimCookie(cookie, now) || l.claimCookie(cookie, now.Add(time.Minute)) || !l.claimCookie(cookie, now.Add(6*time.Minute)) {
		t.Fatal("incorrect service-wide cookie replay interval")
	}
}
