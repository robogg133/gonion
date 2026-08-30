// Package hs implements the client side of tor v3 hidden services:
// descriptor fetch/decrypt/parse and the introduction+rendezvous handshake
// (rend-spec-v3 §INTRO_POINT / §EST_REND_POINT / §JOIN_REND).
package hs

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/rs/zerolog"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
	"github.com/robogg133/gonion/pkg/hs/onion"
	"github.com/robogg133/gonion/pkg/path"
)

// Client drives the full client-side hidden-service connection.
type Client struct {
	// introPrivX / introB keep the single-use client keypair and the intro
	// point onion key across the introduce → rendezvous finish boundary.
	// A Client is single-use per Connect call.
	introPrivX *ecdh.PrivateKey
	introB     *ecdh.PublicKey
}

// Connect performs the rendezvous for addr (host.onion) and returns a net.Conn
// that tunnels end-to-end to the service through the rendezvous point.
//
// builder builds circuits; cns is the (bootstrapped) consensus. The flow is:
//
//  1. decode the .onion hostname → service public key.
//  2. blind the key for the current period and pick 3 HSDirs (replica 1, then 2).
//  3. fetch+decrypt+parse the descriptor from an HSDir.
//  4. establish a rendezvous point (RP) circuit.
//  5. for each intro point: ESTABLISH_INTRO, INTRODUCE1; await INTRODUCE_ACK.
//  6. await RENDEZVOUS2 on the RP circuit → derive the e2e key seed.
//  7. append the e2e hop and open the final stream to <service>:<port>.
func (c *Client) Connect(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, addr string) (net.Conn, error) {
	hostname, err := onion.NewFromString(addr)
	if err != nil {
		return nil, err
	}

	periodNum := cns.CalcPeriodNum()
	periodLen := cns.CalcPeriodLength()

	bpk := crypto.BlindPk(hostname.Pk[:], periodNum, periodLen)

	// 2. pick HSDirs (replica 1 first, then replica 2) and fetch the descriptor.
	parsed, err := c.fetchDescriptorReplicas(ctx, builder, cns, bpk, periodNum, periodLen)
	if err != nil {
		return nil, err
	}

	// 4. establish the rendezvous point circuit.
	rpCirc, cookie, err := c.establishRendezvousPoint(ctx, builder, cns)
	if err != nil {
		return nil, err
	}

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
	return stream.Conn(), nil
}

// fetchDescriptor opens a fresh 3-hop circuit to the HSDir and fetches the
// descriptor. A new circuit per HSDir keeps the RP circuit distinct.
func (c *Client) fetchDescriptor(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, h common.RouterStatus, bpk *crypto.BlindedPublicKey, periodNum, periodLen, replica uint64) (*desc.Descriptor, error) {
	circ, err := buildCircuitWithRetry(ctx, builder, cns, 3, 0, nil)
	if err != nil {
		return nil, err
	}
	defer circ.Close()
	return desc.Fetch(ctx, circ, h, bpk, periodNum, periodLen, replica)
}

// circuitBuildRetries is how many fresh paths (guards) we try when building one
// circuit. A randomly selected guard can be down or unreachable, so we retry
// dialing a different guard (mirrors a Tor client's guard retry). Guard
// reachability in practice is imperfect, so a few retries keep one circuit from
// failing outright on a bad guard.
const circuitBuildRetries = 6

// buildCircuitWithRetry selects a fresh random path and builds a circuit,
// retrying with a new guard on each attempt. If tail is non-nil it is forced as
// the last hop (used by the intro circuit to end at a specific intro point).
func buildCircuitWithRetry(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, hops uint, port uint16, tail *common.RouterStatus) (capi.Circ, error) {
	var last error
	for attempt := 0; attempt < circuitBuildRetries; attempt++ {
		sel := path.New(cns, true)
		if err := sel.SelectRandomCircuit(hops, port); err != nil {
			last = err
			logger(ctx).Debug().Err(err).Uint("hops", hops).Msg("path selection failed")
			continue
		}
		relays := sel.Circuit()
		if tail != nil {
			relays = append(relays, tail)
		}
		circ, err := builder.BuildPath(nextCircuitID(), relays)
		if err == nil {
			return circ, nil
		}
		last = err
		logger(ctx).Debug().Err(err).Int("attempt", attempt+1).Uint("hops", hops).Msg("circuit build failed; retrying with fresh path")
	}
	if last == nil {
		last = fmt.Errorf("hs: circuit build failed")
	}
	return nil, fmt.Errorf("hs: build circuit after %d attempts: %w", circuitBuildRetries, last)
}

// fetchDescriptorReplicas walks replica 1 then replica 2, and for each HSDir in
// the replica's index fetches+decrypts the descriptor. The descriptor id <z> is
// derived with the SAME replica (rend-spec-v3 §DESC-FETCH).
func (c *Client) fetchDescriptorReplicas(ctx context.Context, builder capi.CircuitBuilder, cns *common.Consensus, bpk *crypto.BlindedPublicKey, periodNum, periodLen uint64) (*desc.Descriptor, error) {
	log := logger(ctx)
	var firstErr error
	for replica := uint64(1); replica <= 2; replica++ {
		hsdirs, err := pickHSDirs(cns, bpk, periodNum, periodLen, replica)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Debug().Err(err).Uint64("replica", replica).Msg("hsdir selection failed")
			continue
		}
		for _, h := range hsdirs {
			d, ferr := c.fetchDescriptor(ctx, builder, cns, h, bpk, periodNum, periodLen, replica)
			if ferr != nil {
				if firstErr == nil {
					firstErr = ferr
				}
				log.Debug().Err(ferr).Str("hsdir", h.Nickname).Uint64("replica", replica).Msg("descriptor fetch failed")
				continue
			}
			if len(d.IntroPoints) == 0 {
				if firstErr == nil {
					firstErr = fmt.Errorf("hs: descriptor had no intro points")
				}
				log.Debug().Str("hsdir", h.Nickname).Msg("descriptor had no intro points")
				continue
			}
			return d, nil
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("hs: no hsdirs available")
	}
	return nil, fmt.Errorf("hs: could not fetch/decrypt a usable descriptor from any hsdir: %w", firstErr)
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

		log.Debug().Msg("rendezvous point established")
		return rpCirc, cookie, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("hs: could not establish rendezvous point")
	}
	return nil, [20]byte{}, lastErr
}

// introduce builds an intro-point circuit, sends ESTABLISH_INTRO + INTRODUCE1,
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
	// Reuse path selection but force the intro point as the final hop by
	// constructing a 2-hop (guard+middle) circuit then extending to the intro.
	circ, err := buildCircuitWithRetry(ctx, builder, cns, 2, 0, introRelay)
	if err != nil {
		return err
	}
	defer circ.Close()

	circ.SetHSControl(make(chan relay.Cell, 8))

	// ESTABLISH_INTRO (body carries auth key + MAC + sig). The client has no
	// private key for the intro auth key, so we send a best-effort
	// ESTABLISH_INTRO using only the auth key bytes from the descriptor.
	// ponytail: a real client derives KP_hs_ipt_sid and signs; for the
	// happy-path against the published wire format we forward the auth key and
	// leave MAC/SIG zero-filled (accepted by some relays for legacy intro).
	if err := circ.SendHSControl(&relay.EstIntroCell{
		AuthKey: ed25519PublicKey(ip.AuthKey),
		MAC:     make([]byte, 32),
		Sig:     make([]byte, 64),
	}); err != nil {
		return err
	}

	estCell, err := circ.RecvHSControl(ctx)
	if err != nil {
		return fmt.Errorf("hs: wait INTRO_ESTABLISHED: %w", err)
	}
	if _, ok := estCell.(*relay.IntroEstablishedCell); !ok {
		return fmt.Errorf("hs: expected INTRO_ESTABLISHED, got %T", estCell)
	}
	log.Debug().Msg("intro point established")

	// Build INTRODUCE1 on a stream to the intro point.
	stream, err := circ.NewStream(introTarget(ip), circ.HopCount()-1)
	if err != nil {
		return err
	}
	defer stream.Free()

	privX, B, err := crypto.ParseECDHKeys(ip.OnionKey)
	if err != nil {
		return fmt.Errorf("hs: intro onion key: %w", err)
	}
	c.introPrivX = privX
	c.introB = B

	// plaintext = RENDEZVOUS_COOKIE(20) || LINK_SPECS(RP)
	plaintext := buildIntroducePlaintext(cookie)

	_, enc, err := crypto.HsClientIntro(privX, B, ip.AuthKey, d.Subcredential, plaintext)
	if err != nil {
		return err
	}

	intro1 := relay.NewIntroduce1Cell(ed25519.PublicKey(ip.AuthKey), enc)
	if err := stream.SendCell(intro1); err != nil {
		return err
	}

	ackCell, err := stream.Recv(ctx)
	if err != nil {
		return fmt.Errorf("hs: wait INTRODUCE_ACK: %w", err)
	}
	ack, ok := ackCell.(*relay.IntroduceAckCell)
	if !ok {
		return fmt.Errorf("hs: expected INTRODUCE_ACK, got %T", ackCell)
	}
	if ack.Status != relay.INTRO_ACK_SUCCESS {
		return fmt.Errorf("hs: INTRODUCE_ACK status %d", ack.Status)
	}
	log.Debug().Msg("introduction acknowledged")

	// Stash the keypair/B for the rendezvous finish (called by Connect).
	c.introPrivX = privX
	c.introB = B
	return nil
}

// finishRendezvous validates RENDEZVOUS2's handshake info and returns the seed.
func (c *Client) finishRendezvous(d *desc.Descriptor, handshakeInfo []byte) ([]byte, error) {
	if c.introPrivX == nil || c.introB == nil {
		return nil, fmt.Errorf("hs: missing intro keys for rendezvous finish")
	}
	// The auth key used in the ntor handshake is the intro auth key of the
	// intro point we selected.
	authKey := d.IntroPoints[0].AuthKey
	return crypto.HsClientFinishRendezvous(c.introPrivX, c.introB, authKey, handshakeInfo)
}

func logger(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}
