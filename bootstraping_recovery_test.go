package gonion

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
)

type recoveryPinConn struct {
	net.Conn
	pin [20]byte
}

func (c recoveryPinConn) ExpectedRelayIdentity() [20]byte { return c.pin }

func TestRecoveryRejectsMissingPolicyAndChangedPin(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate an already lost bootstrap link
	id := [20]byte{1}
	owner := &Conn{ctx: ctx, relayRSA: id, consensus: cns}
	if _, err := owner.refreshOnce(context.Background(), cns, nil, id, nil); err == nil {
		t.Fatal("lost link recovered without caller dialer")
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	called := 0
	dial := func(context.Context) (net.Conn, error) {
		called++
		return recoveryPinConn{Conn: raw, pin: [20]byte{2}}, nil
	}
	if _, err := owner.refreshOnce(context.Background(), cns, dial, id, nil); err == nil || called != 1 {
		t.Fatalf("mismatched redial pin accepted: %v, calls=%d", err, called)
	}
	if _, err := peer.Write([]byte{1}); err == nil {
		t.Fatal("rejected connection remained open")
	}
	noDial := func(context.Context) (net.Conn, error) { return nil, errors.New("offline") }
	if _, err := owner.refreshOnce(context.Background(), cns, noDial, id, nil); err == nil {
		t.Fatal("dial failure ignored")
	}
}

func TestPinnedRecoveryReplacesDeadChannel(t *testing.T) {
	oldCtx, killOld := context.WithCancelCause(context.Background())
	oldRaw, oldPeer := net.Pipe()
	defer oldPeer.Close()
	killOld(errors.New("link lost"))
	id, ed := [20]byte{4}, [32]byte{8}
	owner := &Conn{ctx: oldCtx, ctxCancel: killOld, socket: oldRaw, relayRSA: id, relayEd: ed}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, peer := net.Pipe()
	defer peer.Close()
	dials, opens := 0, 0
	link, stop, err := owner.reconnect(ctx, func(context.Context) (net.Conn, error) {
		dials++
		return recoveryPinConn{Conn: raw, pin: id}, nil
	}, id, nil, func(raw net.Conn) (*Conn, error) {
		opens++
		live, closeLink := context.WithCancelCause(context.Background())
		return &Conn{ctx: live, ctxCancel: closeLink, socket: raw, relayRSA: id, relayEd: ed}, nil
	})
	if err != nil || dials != 1 || opens != 1 || link == nil || owner.recoveryConn != link {
		t.Fatalf("pinned recovery failed: %v; calls %d/%d", err, dials, opens)
	}
	if _, err := oldPeer.Write([]byte{1}); err == nil {
		t.Fatal("dead original channel retained")
	}
	// Set the write deadline before cancel: whether the channel AfterFunc
	// fires first only changes the failure shape, not that the write must
	// fail, and a deadline set on a closed pipe would misattribute it.
	if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := peer.Write([]byte{1}); err == nil {
		t.Fatal("canceled recovery retained new channel")
	}
	stop()
	_ = owner.Close()
}

func TestDeadOriginalCircuitDoesNotOwnRefresh(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	link, cancelLink := context.WithCancelCause(context.Background())
	defer cancelLink(nil)
	raw, peer := net.Pipe()
	defer peer.Close()
	id := [20]byte{1}
	owner := &Conn{ctx: link, ctxCancel: cancelLink, socket: raw, relayRSA: id, consensus: cns}
	dead, cancelCircuit := context.WithCancel(context.Background())
	cancelCircuit()
	(&Circuit{conn: owner, Ctx: dead}).StartConsensusRefresh(link, cns)
	owner.recoveryMu.Lock()
	started := owner.recoveryCancel != nil
	owner.recoveryMu.Unlock()
	if !started {
		t.Fatal("refresh worker died with original circuit")
	}
	_ = owner.Close()
}

func TestRecoveryWorkerOwnership(t *testing.T) {
	cns := testutil.Consensus(t, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, peer := net.Pipe()
	defer peer.Close()
	id := [20]byte{1}
	owner := &Conn{ctx: ctx, ctxCancel: func(error) { cancel() }, socket: local, relayRSA: id, consensus: cns}
	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if owner.StartConsensusRecovery(nil, id, nil) == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("started %d recovery workers", successes)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if owner.recoveryCancel != nil {
		t.Fatal("close retained worker cancellation")
	}
	if owner.StartConsensusRecovery(nil, id, nil) == nil {
		t.Fatal("closed owner restarted worker")
	}
}

func TestRecoveryRejectsConflictingSignedEpoch(t *testing.T) {
	stamp := time.Now().Truncate(time.Minute)
	first := testutil.Consensus(t, stamp)
	conflict := testutil.Consensus(t, stamp)
	if !first.ValidAfter.Equal(conflict.ValidAfter) || bytes.Equal(first.RawDocument, conflict.RawDocument) {
		t.Fatal("invalid independent signed fixture")
	}
	owner := &Conn{consensus: first}
	owner.publishVerifiedConsensus(context.Background(), conflict)
	if got := owner.Consensus(); !bytes.Equal(got.RawDocument, first.RawDocument) {
		t.Fatal("conflicting signed consensus replaced last good")
	}
}

func TestRecoveryNeverDowngradesPublishedSnapshot(t *testing.T) {
	old := testutil.Consensus(t, time.Now())
	newer := testutil.Consensus(t, time.Now().Add(20*time.Minute))
	owner := &Conn{consensus: newer}
	owner.publishVerifiedConsensus(context.Background(), old)
	if got := owner.Consensus(); got.ValidAfter != newer.ValidAfter || !got.TrustedHydrated() {
		t.Fatal("older authenticated consensus replaced last good")
	}
	if bytes.Equal(old.RawDocument, newer.RawDocument) {
		t.Fatal("fixture epochs not distinct")
	}

}
