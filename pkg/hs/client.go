// Package hs implements Tor v3 onion clients and services: descriptor
// retrieval/publication and introduction/rendezvous (rend-spec-v3).
package hs

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
	"github.com/robogg133/gonion/pkg/hs/onion"
	"github.com/robogg133/gonion/pkg/path"
)

// Client coordinates descriptor retrieval and the introduction/rendezvous handshake.
type Client struct {
	// introPrivX / introB keep the single-use client keypair and the intro
	// point onion key across the introduce → rendezvous finish boundary.
	// Connect uses a separate instance of this state for each call.
	introPrivX      *ecdh.PrivateKey
	introB          *ecdh.PublicKey
	introAuth       []byte
	rendezvousRelay *common.RouterStatus
}

// Connect uses an authenticated live consensus to reach an onion host:port.
// It fetches and validates the descriptor, establishes a rendezvous, introduces
// through a separate circuit, and authenticates the service before BEGIN.
// Closing the returned connection also closes its dedicated rendezvous circuit.
func (c *Client) Connect(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, addr string) (net.Conn, error) {
	// Keep ephemeral handshake state private to this call, including retries.
	c = &Client{}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if builder == nil || !cns.IsAuthenticated() || !cns.IsLive(time.Now()) {
		return nil, fmt.Errorf("hs: an authenticated live consensus and circuit builder are required")
	}
	_, port, err := net.SplitHostPort(addr)
	p, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || p == 0 {
		return nil, fmt.Errorf("hs: invalid onion dial address")
	}
	hostname, err := onion.NewFromString(addr)
	if err != nil {
		return nil, err
	}

	periodNum := cns.CalcPeriodNum()
	periodLen := cns.CalcPeriodLength()

	bpk, err := crypto.BlindPublicKey(hostname.Pk[:], periodNum, periodLen)
	if err != nil {
		return nil, err
	}

	// Fetch from the responsible HSDirs in random order.
	parsed, err := c.fetchDescriptorReplicas(ctx, builder, cns, bpk, periodNum, periodLen)
	if err != nil {
		return nil, err
	}

	if len(parsed.IntroAuthRequired) != 0 || !slices.Contains(parsed.Create2Formats, uint16(2)) {
		return nil, fmt.Errorf("hs: descriptor requires unsupported introduction authentication or handshake")
	}
	// 4. establish the rendezvous point circuit.
	rpCirc, cookie, err := c.establishRendezvousPoint(ctx, builder, cns)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { _ = rpCirc.Close() })
	defer stop()
	// 5. introduce to an intro point (build intro circuit, INTRODUCE1).
	if err := c.introduce(ctx, builder, cns, rpCirc, cookie, parsed); err != nil {
		_ = rpCirc.Close()
		return nil, err
	}

	// 6. await RENDEZVOUS2 on the RP circuit.
	handshakeInfo, err := recvRendezvous2(ctx, rpCirc)
	if err != nil {
		_ = rpCirc.Close()
		return nil, err
	}

	// Derive the e2e key seed from the rendezvous handshake. We need the
	// client's single-use keypair x and the intro point onion key B, which the
	// intro step keeps. The intro step returns them.
	seed, err := c.finishRendezvous(parsed, handshakeInfo)
	if err != nil {
		_ = rpCirc.Close()
		return nil, err
	}

	// 7. append the e2e hop and open the stream.
	keys, err := crypto.E2EKeys(seed, parsed.Subcredential)
	if err != nil {
		_ = rpCirc.Close()
		return nil, err
	}
	if err := rpCirc.AppendE2EHop(keys.Kf, keys.Kb, keys.Df, keys.Db); err != nil {
		_ = rpCirc.Close()
		return nil, err
	}

	serviceAddr := serviceStreamTarget(addr)
	stream, err := rpCirc.NewStream(serviceAddr, rpCirc.HopCount()-1)
	if err != nil {
		_ = rpCirc.Close()
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		_ = rpCirc.Close()
		return nil, ctx.Err()
	}
	return &rendezvousConn{Conn: stream.Conn(), circuit: rpCirc}, nil
}

// fetchDescriptor opens a fresh 3-hop circuit to the HSDir and fetches the
// descriptor. A new circuit per HSDir keeps the RP circuit distinct.
func (c *Client) fetchDescriptor(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, h common.RouterStatus, bpk *crypto.BlindedPublicKey, periodNum, periodLen, replica uint64) (*desc.Descriptor, error) {
	circ, err := buildCircuitWithRetry(ctx, builder, cns, 3, 0, &h)
	if err != nil {
		return nil, err
	}
	defer circ.Close()
	return desc.Fetch(ctx, circ, h, bpk, periodNum, periodLen, replica)
}

// circuitBuildRetries bounds fresh-path attempts. Guard selection is currently
// stateless; these retries do not implement Tor's persistent guard algorithm.
const circuitBuildRetries = 6

// buildCircuitWithRetry selects a fresh random path and builds a circuit,
// retrying with a new guard on each attempt. If tail is non-nil it is forced as
// the last hop (used by the intro circuit to end at a specific intro point).
func buildCircuitWithRetry(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, hops uint, port uint16, tail *common.RouterStatus) (capi.Circ, error) {
	var last error
	for attempt := 0; attempt < circuitBuildRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		sel := path.New(cns, true)
		var err error
		if tail == nil && port == 0 {
			var target *common.RouterStatus
			target, err = sel.SelectHSRelay(false)
			if err == nil {
				err = sel.SelectCircuitTo(hops, target)
			}
		} else if tail == nil {
			err = sel.SelectRandomCircuit(hops, port)
		} else {
			err = sel.SelectCircuitTo(hops, tail)
		}
		if err != nil {
			last = err
			logger(ctx).Debug().Err(err).Uint("hops", hops).Msg("path selection failed")
			continue
		}
		relays := sel.Circuit()
		var circ capi.Circ
		if cb, ok := builder.(capi.ContextCircuitBuilder); ok {
			attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			circ, err = cb.BuildPathContext(attemptCtx, nextCircuitID(), relays)
			cancel()
		} else {
			circ, err = builder.BuildPath(nextCircuitID(), relays)
		}
		if err == nil {
			return &pathCircuit{Circ: circ, final: relays[len(relays)-1]}, nil
		}
		last = err
		logger(ctx).Debug().Err(err).Int("attempt", attempt+1).Uint("hops", hops).Msg("circuit build failed; retrying with fresh path")
	}
	if last == nil {
		last = fmt.Errorf("hs: circuit build failed")
	}
	return nil, fmt.Errorf("hs: build circuit after %d attempts: %w", circuitBuildRetries, last)
}

// Replicas select directories, not URLs. Never query the same relay twice for
// one fetch attempt (rend-spec-v3 WHERE-HSDESC).
func (c *Client) fetchDescriptorReplicas(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, bpk *crypto.BlindedPublicKey, periodNum, periodLen uint64) (*desc.Descriptor, error) {
	hsdirs, err := responsibleHSDirs(cns, bpk, periodNum, periodLen)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for len(hsdirs) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(hsdirs))))
		if err != nil {
			return nil, err
		}
		i := int(n.Int64())
		h := hsdirs[i]
		hsdirs[i] = hsdirs[len(hsdirs)-1]
		hsdirs = hsdirs[:len(hsdirs)-1]
		d, err := c.fetchDescriptor(ctx, builder, cns, h, bpk, periodNum, periodLen, 0)
		if err == nil && len(d.IntroPoints) != 0 {
			return d, nil
		}
		if err == nil {
			err = fmt.Errorf("hs: descriptor has no introduction points")
		}
		lastErr = err
		logger(ctx).Debug().Err(err).Str("hsdir", h.Nickname).Msg("descriptor fetch failed")
	}
	return nil, fmt.Errorf("hs: no usable descriptor from responsible HSDirs: %w", lastErr)
}

// establishRendezvousPoint builds a long-lived circuit and sends
// ESTABLISH_RENDEZVOUS, returning the circuit and the rendezvous cookie.
func (c *Client) establishRendezvousPoint(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus) (capi.Circ, [20]byte, error) {
	log := logger(ctx)

	var lastErr error
	for attempt := 0; attempt < circuitBuildRetries; attempt++ {
		// buildCircuitWithRetry already exhausts the guard-dial retry budget
		// internally, so a build failure here is terminal for this attempt.
		rpCirc, err := buildCircuitWithRetry(ctx, builder, cns, 3, 0, nil)
		if err != nil {
			return nil, [20]byte{}, err
		}

		// The outer loop only retries the ESTABLISH_RENDEZVOUS protocol
		// exchange (e.g. the RP never acked), on a fresh circuit.

		var cookie [20]byte
		if _, err := rand.Read(cookie[:]); err != nil {
			_ = rpCirc.Close()
			return nil, [20]byte{}, err
		}

		rpCirc.SetHSControl(make(chan relay.Cell, 8))

		if err := rpCirc.SendHSControl(&relay.EstRendezvousCell{Cookie: cookie}); err != nil {
			_ = rpCirc.Close()
			lastErr = err
			continue
		}

		// Await RENDEZVOUS_ESTABLISHED.
		cell, err := rpCirc.RecvHSControl(ctx)
		if err != nil {
			_ = rpCirc.Close()
			lastErr = fmt.Errorf("hs: wait RENDEZVOUS_ESTABLISHED: %w", err)
			continue
		}
		if _, ok := cell.(*relay.RendezvousEstablishedCell); !ok {
			_ = rpCirc.Close()
			lastErr = fmt.Errorf("hs: expected RENDEZVOUS_ESTABLISHED, got %T", cell)
			continue
		}

		c.rendezvousRelay = rpCirc.(*pathCircuit).final
		log.Debug().Msg("rendezvous point established")
		return rpCirc, cookie, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("hs: could not establish rendezvous point")
	}
	return nil, [20]byte{}, lastErr
}

// introduce builds an intro-point circuit, sends INTRODUCE1 as a control cell,
// and waits for INTRODUCE_ACK SUCCESS. It keeps the client keypair and intro
// onion key needed to finish the rendezvous.
func (c *Client) introduce(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, rpCirc capi.Circ, cookie [20]byte, d *desc.Descriptor) error {
	var lastErr error
	for _, ip := range d.IntroPoints {
		if err := c.tryIntro(ctx, builder, cns, rpCirc, cookie, d, ip); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("hs: no intro points")
	}
	return lastErr
}

func (c *Client) tryIntro(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, rpCirc capi.Circ, cookie [20]byte, d *desc.Descriptor, ip desc.IntroPoint) error {
	log := logger(ctx)

	// Build circuit: guard + middle + intro point.
	introRelay := relayStatusFromSpecs(ip.LinkSpecs)
	if introRelay == nil {
		return fmt.Errorf("hs: intro point has no usable link specifiers")
	}
	var err error
	introRelay.NTorOnionKey, err = ecdh.X25519().NewPublicKey(ip.OnionKey)
	if err != nil {
		return err
	}
	introRelay.LinkSpecifiers = append([]byte(nil), ip.LinkSpecifiers...)
	circ, err := buildCircuitWithRetry(ctx, builder, cns, 3, 0, introRelay)
	if err != nil {
		return err
	}
	defer circ.Close()

	circ.SetHSControl(make(chan relay.Cell, 8))

	privX, B, err := crypto.ParseECDHKeys(ip.EncKey)
	if err != nil {
		return fmt.Errorf("hs: intro onion key: %w", err)
	}

	plaintext, err := buildIntroducePlaintext(cookie, c.rendezvousRelay)
	if err != nil {
		return err
	}

	_, enc, err := crypto.HsClientIntro(privX, B, ip.AuthKey, d.Subcredential, plaintext)
	if err != nil {
		return err
	}

	if err := sendIntroduction(ctx, circ, ip.AuthKey, enc); err != nil {
		return err
	}
	log.Debug().Msg("introduction acknowledged")

	// Stash the keypair/B for the rendezvous finish (called by Connect).
	c.introPrivX = privX
	c.introB = B
	c.introAuth = append([]byte(nil), ip.AuthKey...)
	return nil
}

// sendIntroduction never creates a stream or establishes an introduction point:
// those operations belong to BEGIN and the service, respectively.
func sendIntroduction(ctx context.Context, circ capi.Circ, authKey, encrypted []byte) error {
	intro := relay.NewIntroduce1Cell(ed25519.PublicKey(authKey), encrypted)
	if err := circ.SendHSControl(intro); err != nil {
		return err
	}
	cell, err := circ.RecvHSControl(ctx)
	if err != nil {
		return fmt.Errorf("hs: wait INTRODUCE_ACK: %w", err)
	}
	ack, ok := cell.(*relay.IntroduceAckCell)
	if !ok {
		return fmt.Errorf("hs: expected INTRODUCE_ACK, got %T", cell)
	}
	if ack.Status != relay.INTRO_ACK_SUCCESS {
		return fmt.Errorf("hs: INTRODUCE_ACK status %d", ack.Status)
	}
	return nil
}

// finishRendezvous validates RENDEZVOUS2's handshake info and returns the seed.
func (c *Client) finishRendezvous(_ *desc.Descriptor, handshakeInfo []byte) ([]byte, error) {
	if c.introPrivX == nil || c.introB == nil || len(c.introAuth) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("hs: missing intro keys for rendezvous finish")
	}
	return crypto.HsClientFinishRendezvous(c.introPrivX, c.introB, c.introAuth, handshakeInfo)
}

type pathCircuit struct {
	capi.Circ
	final *common.RouterStatus
}

type rendezvousConn struct {
	net.Conn
	circuit capi.Circ
	once    sync.Once
}

func (c *rendezvousConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); _ = c.circuit.Close() })
	return err
}

func logger(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}
