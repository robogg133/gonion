package hs

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
	"github.com/robogg133/gonion/pkg/lspec"
)

const maxIntroductionReplays = 4096

var (
	errIntroductionReplay = errors.New("hs: replayed introduction")
	errReplayCacheFull    = errors.New("hs: introduction replay cache exhausted")
)

type serviceIntroduction struct {
	circuit       capi.ServiceCirc
	key           *ecdh.PrivateKey
	subcredential []byte
	descriptor    desc.IntroPoint
	// Owned by receiveIntroductions. Never evict while this key accepts cells.
	cells   map[[32]byte]struct{}
	cookies map[[20]byte]struct{}
}

type introductionRequest struct {
	cookie            [20]byte
	target            *common.RouterStatus
	clientKey         *ecdh.PublicKey
	congestionControl bool
}

// parseIntroductionPlaintext follows rend-spec-v3 PROCESS_INTRO2. PAD is not
// part of the NSPEC block: forward only the original link specifiers verbatim.
func parseIntroductionPlaintext(plain []byte) (*introductionRequest, error) {
	if len(plain) < 21 || len(plain) > relay.RELAY_BODY_LEN-56-64 {
		return nil, fmt.Errorf("hs: invalid introduction plaintext length")
	}
	r := &introductionRequest{cookie: [20]byte(plain[:20])}
	pos := 21
	for n := 0; n < int(plain[20]); n++ {
		if len(plain)-pos < 2 || int(plain[pos+1]) > len(plain)-pos-2 {
			return nil, fmt.Errorf("hs: truncated introduction extension")
		}
		// C Tor cell_introduce1.h: type 1 requests negotiated congestion
		// control. Our descriptor does not advertise flow-control=2.
		if plain[pos] == 1 {
			r.congestionControl = true
		}
		pos += 2 + int(plain[pos+1])
	}
	if len(plain)-pos < 36 || plain[pos] != 1 || binary.BigEndian.Uint16(plain[pos+1:pos+3]) != 32 {
		return nil, fmt.Errorf("hs: invalid rendezvous onion key")
	}
	key, err := ecdh.X25519().NewPublicKey(plain[pos+3 : pos+35])
	if err != nil {
		return nil, err
	}
	// This scalar only validates public input; it is never a protocol secret.
	probe, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if _, err := probe.ECDH(key); err != nil {
		return nil, fmt.Errorf("hs: low-order rendezvous onion key")
	}
	pos += 35
	reader := bytes.NewReader(plain[pos+1:])
	var specs []lspec.Lspec
	for n := 0; n < int(plain[pos]); n++ {
		s, err := lspec.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("hs: invalid rendezvous link specifier: %w", err)
		}
		specs = append(specs, s)
	}
	r.target = relayStatusFromSpecs(specs)
	if r.target == nil {
		return nil, fmt.Errorf("hs: missing or invalid rendezvous link specifiers")
	}
	r.target.NTorOnionKey = key
	r.target.LinkSpecifiers = bytes.Clone(plain[pos : len(plain)-reader.Len()])
	return r, nil
}

func (ip *serviceIntroduction) decrypt(cell *relay.Introduce2Cell) (*introductionRequest, error) {
	if cell.LegacyKeyID != [20]byte{} || !bytes.Equal(cell.AuthKey, ip.descriptor.AuthKey) {
		return nil, fmt.Errorf("hs: introduction authentication key mismatch")
	}
	header, err := cell.Header()
	if err != nil || len(header)+len(cell.Payload) > relay.RELAY_BODY_LEN {
		return nil, fmt.Errorf("hs: invalid introduction header")
	}
	digest := sha3.Sum256(append(header, cell.Payload...))
	if _, seen := ip.cells[digest]; seen {
		return nil, errIntroductionReplay
	}
	if len(ip.cells) >= maxIntroductionReplays {
		return nil, errReplayCacheFull
	}
	if ip.cells == nil {
		ip.cells = make(map[[32]byte]struct{})
		ip.cookies = make(map[[20]byte]struct{})
	}
	ip.cells[digest] = struct{}{}
	clientKey, plain, err := crypto.HsServiceIntroWithHeader(ip.key, ip.descriptor.AuthKey, ip.subcredential, header, cell.Payload)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	r, err := parseIntroductionPlaintext(plain)
	if err != nil {
		return nil, err
	}
	if r.congestionControl {
		return nil, fmt.Errorf("hs: unadvertised congestion control requested")
	}
	if _, seen := ip.cookies[r.cookie]; seen {
		return nil, errIntroductionReplay
	}
	ip.cookies[r.cookie] = struct{}{}
	r.clientKey = clientKey
	return r, nil
}

func (l *Listener) receiveIntroductions(ip *serviceIntroduction) {
	defer ip.circuit.Close()
	for {
		cell, err := ip.circuit.RecvHSControl(l.ctx)
		if err != nil {
			return
		}
		intro, ok := cell.(*relay.Introduce2Cell)
		if !ok {
			return
		}
		r, err := ip.decrypt(intro)
		if errors.Is(err, errReplayCacheFull) {
			// Retire this key rather than forgetting replay history. Maintenance
			// will publish a replacement introduction point with a fresh key.
			return
		}
		if err != nil || !l.claimCookie(r.cookie, time.Now()) {
			continue
		}
		select {
		case l.slots <- struct{}{}:
			go l.joinIntroduction(ip, r)
		case <-l.ctx.Done():
			return
		default:
			// Bound circuit builds and established rendezvous circuits together.
		}
	}
}

// Suppress retries through different intro keys too, as C Tor's service-wide
// REND_REPLAY_TIME_INTERVAL cache does. Per-key cookie history above lasts for
// the entire encryption-key lifetime, not just this five-minute interval.
func (l *Listener) claimCookie(cookie [20]byte, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.nextReplayPrune) {
		for k, expiry := range l.cookieReplay {
			if !now.Before(expiry) {
				delete(l.cookieReplay, k)
			}
		}
		l.nextReplayPrune = now.Add(time.Minute)
	}
	if expiry, seen := l.cookieReplay[cookie]; seen && now.Before(expiry) {
		return false
	}
	if l.ctx.Err() != nil || len(l.cookieReplay) >= 32768 {
		return false
	}
	if l.cookieReplay == nil {
		l.cookieReplay = make(map[[20]byte]time.Time)
	}
	l.cookieReplay[cookie] = now.Add(5 * time.Minute)
	return true
}

func (l *Listener) joinIntroduction(ip *serviceIntroduction, r *introductionRequest) {
	registered := false
	defer func() {
		if !registered {
			<-l.slots
		}
	}()
	ctx, cancel := context.WithTimeout(l.ctx, 90*time.Second)
	defer cancel()
	l.mu.Lock()
	cns := l.current
	l.mu.Unlock()
	if !cns.IsAuthenticated() || !cns.IsLive(time.Now()) {
		return
	}
	y, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	reply, seed, err := crypto.HsServiceRendezvous(r.clientKey, ip.key.PublicKey(), ip.descriptor.AuthKey, ip.key, y)
	if err != nil {
		return
	}
	defer clear(seed)
	keys, err := crypto.E2EKeys(seed, ip.subcredential)
	if err != nil {
		return
	}
	defer clear(keys.Kf)
	defer clear(keys.Kb)
	defer clear(keys.Df)
	defer clear(keys.Db)
	pc, err := buildCircuitWithRetry(ctx, l.builder, cns, 3, 0, r.target)
	if err != nil {
		logger(l.ctx).Debug().Err(err).Msg("service rendezvous circuit build failed")
		return
	}
	sc, ok := pc.(*pathCircuit).Circ.(capi.ServiceCirc)
	if !ok {
		_ = pc.Close()
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = sc.Close() })
	err = sc.JoinRendezvous(r.cookie, reply, keys.Kf, keys.Kb, keys.Df, keys.Db, l.address.String())
	stopped := stop()
	l.mu.Lock()
	if err != nil || !stopped || ctx.Err() != nil || l.ctx.Err() != nil || sc.Ctx().Err() != nil {
		l.mu.Unlock()
		_ = sc.Close()
		return
	}
	l.rendezvous[sc] = struct{}{}
	registered = true
	l.mu.Unlock()
	context.AfterFunc(sc.Ctx(), func() {
		l.mu.Lock()
		delete(l.rendezvous, sc)
		l.mu.Unlock()
		<-l.slots
	})
	go l.acceptRendezvous(sc)
}

func (l *Listener) acceptRendezvous(sc capi.ServiceCirc) {
	defer sc.StopAccepting()
	active := new(atomic.Int32)
	for {
		ctx, cancel := context.WithTimeout(l.ctx, 2*time.Minute)
		conn, err := sc.AcceptStream(ctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) && active.Load() != 0 {
			continue
		}
		if err != nil {
			return
		}
		active.Add(1)
		wrapped := &serviceConn{Conn: conn, active: active}
		l.mu.Lock()
		queued := false
		if l.ctx.Err() == nil {
			select {
			case l.incoming <- wrapped:
				queued = true
			default:
			}
		}
		l.mu.Unlock()
		if !queued {
			_ = wrapped.Close()
			if l.ctx.Err() != nil {
				return
			}
		}
	}
}

var _ net.Conn = (*serviceConn)(nil)
