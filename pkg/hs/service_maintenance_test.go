package hs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/crypto"
)

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
		consensus: func() *common.Consensus { return cns },
		descriptors: map[descriptorPeriod]*serviceDescriptor{periods[0]: first, periods[1]: second},
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
