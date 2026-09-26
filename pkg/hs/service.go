package hs

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
	"github.com/robogg133/gonion/pkg/hs/onion"
	"github.com/robogg133/gonion/pkg/path"
)

// ServiceOptions leaves identity generation and persistence to the application.
// Temporary introduction/signing keys and replay caches live only in memory.
type ServiceOptions struct {
	Identity ed25519.PrivateKey
	Port     uint16
	// NextRevision must atomically reserve and persist a strictly increasing
	// revision for this blinded identity BEFORE returning it. It must honor ctx.
	// An ephemeral identity may use an application-owned in-memory counter.
	NextRevision func(ctx context.Context, blinded [32]byte) (uint64, error)
}

func (o ServiceOptions) Validate() error {
	if len(o.Identity) != ed25519.PrivateKeySize || o.Port == 0 || o.NextRevision == nil {
		return fmt.Errorf("hs: identity, nonzero virtual port and revision allocator are required")
	}
	key := ed25519.NewKeyFromSeed(o.Identity[:32])
	defer clear(key)
	if !bytes.Equal(key, o.Identity) {
		return fmt.Errorf("hs: inconsistent service identity")
	}
	return crypto.ValidateEd25519PublicKey(o.Identity[32:])
}

type serviceAddress string

func (a serviceAddress) Network() string { return "tor" }
func (a serviceAddress) String() string  { return string(a) }

type descriptorPeriod struct{ number, length uint64 }
type serviceDescriptor struct {
	period                     descriptorPeriod
	blinded                    *crypto.BlindedPrivateKey
	signing                    ed25519.PrivateKey
	intros                     []*serviceIntroduction
	published, nextPublication time.Time
	directorySet               [32]byte
}

// Listener accepts Tor streams directly. It never binds a local socket.
// Close preserves accepted connections; Shutdown also terminates those streams.
// Local ceilings: 64 queued connections, 32 rendezvous circuits, and 16 active
// or retiring descriptors. Replay caches never evict entries under a live key.
type Listener struct {
	ctx       context.Context
	cancel    context.CancelFunc
	address   serviceAddress
	opts      ServiceOptions
	builder   capi.ContextCircuitBuilder
	consensus func() *common.Consensus
	incoming  chan net.Conn
	slots     chan struct{}
	closeOnce sync.Once

	mu              sync.Mutex
	current         *common.Consensus
	lastErr         error
	introCircuits   map[capi.Circ]struct{}
	rendezvous      map[capi.ServiceCirc]struct{}
	cookieReplay    map[[20]byte]time.Time
	nextReplayPrune time.Time
	// Only the initialization/maintenance goroutine accesses these fields.
	descriptors map[descriptorPeriod]*serviceDescriptor
	retired     []*serviceDescriptor
	revisions   map[[32]byte]uint64
}

// Listen waits for three introduction points per active descriptor and attempts
// every responsible HSDir upload. Each replica of both overlapping descriptors
// must acknowledge at least one upload. This is publication, not a reachability
// guarantee. ctx controls initialization only, not the returned listener's life.
func Listen(ctx context.Context, builder capi.ContextCircuitBuilder, consensus func() *common.Consensus, opts ServiceOptions) (*Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if builder == nil || consensus == nil {
		return nil, fmt.Errorf("hs: context-aware builder and consensus source are required")
	}
	opts.Identity = bytes.Clone(opts.Identity)
	host := (&onion.OnionHostname{Pk: [32]byte(opts.Identity[32:]), Version: 3}).String()
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l := &Listener{ctx: life, cancel: cancel, address: serviceAddress(net.JoinHostPort(host, strconv.Itoa(int(opts.Port)))), opts: opts, builder: builder, consensus: consensus, incoming: make(chan net.Conn, 64), slots: make(chan struct{}, 32), introCircuits: make(map[capi.Circ]struct{}), rendezvous: make(map[capi.ServiceCirc]struct{}), descriptors: make(map[descriptorPeriod]*serviceDescriptor), revisions: make(map[[32]byte]uint64)}
	stop := context.AfterFunc(ctx, func() { _ = l.Shutdown() })
	err := l.renew(ctx)
	stopped := stop()
	if err != nil || !stopped || ctx.Err() != nil {
		_ = l.Shutdown()
		clear(opts.Identity)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
	go l.maintain()
	return l, nil
}

func (l *Listener) Addr() net.Addr { return l.address }
func (l *Listener) Accept() (net.Conn, error) {
	if l.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	select {
	case conn := <-l.incoming:
		if l.ctx.Err() != nil {
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Err reports the latest maintenance failure, cleared after successful renewal.
// No private key or introduction contents are included in maintenance errors.
func (l *Listener) Err() error { l.mu.Lock(); defer l.mu.Unlock(); return l.lastErr }

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.cancel()
		var intros []capi.Circ
		var rendezvous []capi.ServiceCirc
		for c := range l.introCircuits {
			intros = append(intros, c)
		}
		for c := range l.rendezvous {
			rendezvous = append(rendezvous, c)
		}
		var pending []net.Conn
	drain:
		for {
			select {
			case conn := <-l.incoming:
				pending = append(pending, conn)
			default:
				break drain
			}
		}
		l.mu.Unlock()
		for _, c := range intros {
			_ = c.Close()
		}
		for _, c := range rendezvous {
			_ = c.StopAccepting()
		}
		for _, c := range pending {
			_ = c.Close()
		}
	})
	return nil
}

func (l *Listener) Shutdown() error {
	_ = l.Close()
	l.mu.Lock()
	var circuits []capi.ServiceCirc
	for c := range l.rendezvous {
		circuits = append(circuits, c)
	}
	l.mu.Unlock()
	for _, c := range circuits {
		_ = c.Close()
	}
	return nil
}

func (l *Listener) maintain() {
	defer func() {
		clear(l.opts.Identity)
		for _, d := range l.descriptors {
			l.retire(d)
		}
		for _, d := range l.retired {
			l.retire(d)
		}
	}()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(l.ctx, 3*time.Minute)
			err := l.renew(ctx)
			cancel()
			l.mu.Lock()
			l.lastErr = err
			l.mu.Unlock()
		}
	}
}

// servicePeriods implements FIRSTDESCUPLOAD/SECONDDESCUPLOAD: the first
// descriptor always uses previous SRV, the second always uses current SRV.
func servicePeriods(c *common.Consensus) [2]descriptorPeriod {
	p, length := c.CalcPeriodNum(), c.CalcPeriodLength()
	voting := c.CalcSrvVotingInterval() * 60
	srvStart := uint64(c.ValidAfter.Unix()) / (24 * voting) * (24 * voting)
	if p*length*60+c.CalcRotationTimeOffset() >= srvStart && p > 0 {
		p--
	}
	return [2]descriptorPeriod{{p, length}, {p + 1, length}}
}

func (l *Listener) renew(ctx context.Context) error {
	cns := l.consensus()
	if !cns.IsAuthenticated() || !cns.IsLive(time.Now()) {
		// Local expiry must still run while directory recovery is unavailable.
		l.pruneRetired(time.Now())
		return fmt.Errorf("hs: publication requires an authenticated live consensus")
	}
	l.mu.Lock()
	l.current = cns
	l.mu.Unlock()
	now := time.Now()
	periods := servicePeriods(cns)
	for key, d := range l.descriptors {
		if key != periods[0] && key != periods[1] {
			l.retired = append(l.retired, d)
			delete(l.descriptors, key)
		}
	}
	l.pruneRetired(now)
	var failures []error
	for i, p := range periods {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		d := l.descriptors[p]
		if d == nil || !d.healthy() {
			if len(l.descriptors)+len(l.retired) >= 16 {
				failures = append(failures, fmt.Errorf("hs: retiring descriptor limit reached"))
				continue
			}
			replacement, err := l.newDescriptor(ctx, cns, p)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if d != nil {
				l.retired = append(l.retired, d)
			}
			d = replacement
			l.descriptors[p] = d
		}
		srv := sharedRandom(cns, p.number, p.length, i == 1)
		groups, err := hsdirReplicas(cns, d.blinded.PublicKey(), p.number, p.length, srv, true)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		h := sha3.New256()
		for _, group := range groups {
			for _, r := range group {
				h.Write(r.NodeID[:])
			}
		}
		directorySet := [32]byte(h.Sum(nil))
		if now.Before(d.nextPublication) && directorySet == d.directorySet {
			continue
		}
		if err := l.publish(ctx, cns, d, groups); err != nil {
			failures = append(failures, err)
			continue
		}
		d.directorySet = directorySet
	}
	// The overlapping descriptors serve different client consensus periods;
	// failure of one must not suppress maintenance of the other.
	return errors.Join(failures...)
}

func (l *Listener) pruneRetired(now time.Time) {
	kept := l.retired[:0]
	for _, d := range l.retired {
		if !now.Before(d.published.Add(3 * time.Hour)) {
			l.retire(d)
		} else {
			kept = append(kept, d)
		}
	}
	clear(l.retired[len(kept):])
	l.retired = kept
}

func (d *serviceDescriptor) healthy() bool {
	if len(d.intros) != 3 {
		return false
	}
	for _, ip := range d.intros {
		if ip.circuit.Ctx().Err() != nil {
			return false
		}
	}
	return true
}

func (l *Listener) retire(d *serviceDescriptor) {
	for _, ip := range d.intros {
		_ = ip.circuit.Close()
	}
	clear(d.signing)
}

func (l *Listener) newDescriptor(ctx context.Context, cns *common.Consensus, period descriptorPeriod) (*serviceDescriptor, error) {
	blinded, err := crypto.BlindPrivateKey(l.opts.Identity, period.number, period.length)
	if err != nil {
		return nil, err
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	d := &serviceDescriptor{period: period, blinded: blinded, signing: signing}
	cred, err := crypto.GenerateCredential(blinded.PublicKey().Pk())
	if err != nil {
		return nil, err
	}
	sub, err := crypto.GenerateSubCredential(cred, blinded.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	seen := make(map[[20]byte]bool)
	var lastErr error
	for attempts := 0; len(d.intros) < 3 && attempts < 9; attempts++ {
		if err := ctx.Err(); err != nil {
			l.retire(d)
			return nil, err
		}
		var target *common.RouterStatus
		for attempt := 0; attempt < 32; attempt++ {
			target, err = path.New(cns, true).SelectHSRelay(true)
			if err != nil {
				break
			}
			if !seen[target.NodeID] {
				break
			}
			target = nil
		}
		if err != nil || target == nil {
			l.retire(d)
			return nil, fmt.Errorf("hs: insufficient distinct introduction relays")
		}
		seen[target.NodeID] = true
		ip, err := l.establishIntroduction(ctx, cns, target, sub)
		if err != nil {
			lastErr = err
			logger(ctx).Debug().Err(err).Msg("replacing unavailable introduction relay")
			continue
		}
		d.intros = append(d.intros, ip)
		logger(ctx).Debug().Int("established", len(d.intros)).Msg("service introduction established")
	}
	if len(d.intros) != 3 {
		l.retire(d)
		return nil, fmt.Errorf("hs: introduction establishment attempts exhausted: %w", lastErr)
	}
	return d, nil
}

func (l *Listener) establishIntroduction(ctx context.Context, cns *common.Consensus, target *common.RouterStatus, sub []byte) (*serviceIntroduction, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	pc, err := buildCircuitWithRetry(ctx, l.builder, cns, 3, 0, target)
	if err != nil {
		return nil, err
	}
	sc, ok := pc.(*pathCircuit).Circ.(capi.ServiceCirc)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("hs: builder does not support service circuits")
	}
	stop := context.AfterFunc(ctx, func() { _ = sc.Close() })
	defer stop()
	success := false
	defer func() {
		if !success {
			_ = sc.Close()
		}
	}()
	pub, auth, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(auth)
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	links, err := relayLinkSpecifiers(target)
	if err != nil {
		return nil, err
	}
	sc.SetHSControl(make(chan relay.Cell, 32))
	if err := sc.EstablishIntro(auth); err != nil {
		return nil, err
	}
	ack, err := sc.RecvHSControl(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := ack.(*relay.IntroEstablishedCell); !ok {
		return nil, fmt.Errorf("hs: expected INTRO_ESTABLISHED, got %T", ack)
	}
	ip := &serviceIntroduction{circuit: sc, key: enc, subcredential: bytes.Clone(sub), descriptor: desc.IntroPoint{OnionKey: target.NTorOnionKey.Bytes(), EncKey: enc.PublicKey().Bytes(), AuthKey: pub, LinkSpecifiers: links}}
	l.mu.Lock()
	if l.ctx.Err() != nil || !stop() || ctx.Err() != nil {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.introCircuits[sc] = struct{}{}
	l.mu.Unlock()
	context.AfterFunc(sc.Ctx(), func() { l.mu.Lock(); delete(l.introCircuits, sc); l.mu.Unlock() })
	success = true
	go l.receiveIntroductions(ip)
	return ip, nil
}

func (l *Listener) publish(ctx context.Context, cns *common.Consensus, d *serviceDescriptor, groups [][]common.RouterStatus) error {
	key := [32]byte(d.blinded.PublicKey().Bytes())
	revision, err := l.opts.NextRevision(ctx, key)
	if err != nil {
		return fmt.Errorf("hs: reserve descriptor revision: %w", err)
	}
	if old, seen := l.revisions[key]; seen && revision <= old {
		return fmt.Errorf("hs: descriptor revision did not increase")
	}
	l.revisions[key] = revision
	ips := make([]desc.IntroPoint, len(d.intros))
	for i, ip := range d.intros {
		ips[i] = ip.descriptor
	}
	raw, err := desc.Encode(desc.EncodeOptions{BlindedKey: d.blinded, SigningKey: d.signing, RevisionCounter: revision, LifetimeMinutes: 180, CertificateExpiry: time.Now().Add(24 * time.Hour), IntroPoints: ips})
	if err != nil {
		return err
	}
	// At most four dedicated directory circuits are being built/uploaded at
	// once. A single unavailable HSDir must not serialize all other uploads.
	type upload struct {
		group  int
		target common.RouterStatus
	}
	type result struct {
		group int
		err   error
	}
	jobs := make(chan upload)
	results := make(chan result, 4)
	go func() {
		defer close(jobs)
		for i, group := range groups {
			for _, target := range group {
				select {
				case jobs <- upload{i, target}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
				circ, err := buildCircuitWithRetry(attempt, l.builder, cns, 3, 0, &job.target)
				if err == nil {
					err = desc.Publish(attempt, circ, job.target, raw)
					_ = circ.Close()
				}
				cancel()
				results <- result{job.group, err}
			}
		}()
	}
	go func() { workers.Wait(); close(results) }()
	acknowledged := make([]bool, len(groups))
	var lastErr error
	for result := range results {
		if result.err == nil {
			acknowledged[result.group] = true
			// Partial publication also extends the lifetime of these intro keys.
			d.published = time.Now()
			logger(ctx).Debug().Int("replica", result.group+1).Msg("descriptor upload acknowledged")
		} else {
			lastErr = result.err
			logger(ctx).Debug().Err(result.err).Msg("descriptor upload failed")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, ok := range acknowledged {
		if !ok {
			return fmt.Errorf("hs: descriptor replica not published: %w", lastErr)
		}
	}
	delay, err := rand.Int(rand.Reader, big.NewInt(int64(time.Hour)))
	if err != nil {
		return err
	}
	d.nextPublication = time.Now().Add(time.Hour + time.Duration(delay.Int64()))
	return nil
}

type serviceConn struct {
	net.Conn
	active *atomic.Int32
	once   sync.Once
	err    error
}

func (c *serviceConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.active.Add(-1) })
	return c.err
}

var _ net.Listener = (*Listener)(nil)
