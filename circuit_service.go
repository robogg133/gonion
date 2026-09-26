package gonion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"

	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/pkg/cells/relay"
	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/onion"
)

type serviceCircuitState struct {
	ctx      context.Context
	cancel   context.CancelFunc
	address  string
	port     uint16
	incoming chan *Stream
}

// EstablishIntro binds the service's authentication key to this circuit's
// final-hop ntor nonce. RecvHSControl supplies the relay's acknowledgement.
func (c *Circuit) EstablishIntro(auth ed25519.PrivateKey) error {
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	if c.hops.Len() < 3 || c.e2e || c.intro || len(c.lastKH) != 20 {
		return Public(ErrCircuit, "introduction requires a fresh anonymous ntor circuit")
	}
	cell, err := hscrypto.EstablishIntro(auth, c.lastKH)
	if err != nil {
		return err
	}
	c.intro = true
	return c.SendHSControl(cell)
}

// JoinRendezvous installs receive state before RENDEZVOUS1 can elicit BEGIN.
// Service traffic uses the reverse of the client's E2E key directions.
func (c *Circuit) JoinRendezvous(cookie [20]byte, reply, Kf, Kb, Df, Db []byte, address string) error {
	if _, err := onion.NewFromString(address); err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(address)
	p, perr := strconv.ParseUint(port, 10, 16)
	if err != nil || perr != nil || p == 0 || len(reply) != 64 {
		return Public(ErrProtocolViolation, "invalid service rendezvous parameters")
	}
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	if c.hops.Len() < 3 || c.e2e || c.intro {
		return Public(ErrCircuit, "rendezvous requires a fresh anonymous circuit")
	}
	physicalHop := c.hops.Len() - 1
	c.controlMu.Lock()
	ctx, cancel := context.WithCancel(c.Ctx)
	c.service = &serviceCircuitState{ctx: ctx, cancel: cancel, address: address, port: uint16(p), incoming: make(chan *Stream, 16)}
	c.controlMu.Unlock()
	if err := c.appendE2EHop(Kb, Kf, Db, Df); err != nil {
		c.ctxCancel(err)
		return err
	}
	// Match C Tor's legacy-size padding (rend-spec-v3 4.3). The client
	// authenticates only the first 64 bytes of the relayed HANDSHAKE_INFO.
	padded := make([]byte, 148)
	copy(padded, reply)
	if _, err := rand.Read(padded[64:]); err != nil {
		c.ctxCancel(err)
		return err
	}
	if err := c.sendRelay(&relay.Rendezvous1Cell{Cookie: cookie, HandshakeInfo: padded}, physicalHop, false); err != nil {
		c.ctxCancel(err)
		return err
	}
	return nil
}

func (c *Circuit) acceptIncomingBegin(begin *relay.BeginCell, hop int) {
	c.controlMu.RLock()
	state := c.service
	if state == nil || hop != c.hops.Len()-1 || begin.StreamID == 0 {
		c.controlMu.RUnlock()
		c.ctxCancel(Public(ErrProtocolViolation, "BEGIN outside a service rendezvous"))
		return
	}
	c.streamMu.Lock()
	id := begin.StreamID
	if c.usedStreamIDs[id/8]&(1<<(id%8)) != 0 {
		c.streamMu.Unlock()
		c.controlMu.RUnlock()
		c.ctxCancel(Public(ErrProtocolViolation, "reused incoming stream ID"))
		return
	}
	c.usedStreamIDs[id/8] |= 1 << (id % 8)
	_, port, err := net.SplitHostPort(begin.Addrport)
	p, perr := strconv.ParseUint(port, 10, 16)
	c.streams.mu.RLock()
	full := len(c.streams.streams) >= 64
	c.streams.mu.RUnlock()
	if err != nil || perr != nil || p != uint64(state.port) || full || state.ctx.Err() != nil {
		c.streamMu.Unlock()
		c.controlMu.RUnlock()
		c.rejectIncoming(id, hop)
		return
	}
	s := c.newStream(id, "anonymous", hop)
	s.localAddr = shared.NewAddr("tor", state.address)
	c.streamMu.Unlock()
	select {
	case state.incoming <- s:
		c.controlMu.RUnlock()
	default:
		c.controlMu.RUnlock()
		_ = s.End(relay.END_REASON_DONE)
	}
}

func (c *Circuit) rejectIncoming(id uint16, hop int) {
	select {
	case c.writeControl <- RelayOut{Cell: &relay.RelayEndCell{StreamID: id, Reason: relay.END_REASON_DONE}, Dst: hop}:
	case <-c.Ctx.Done():
	default:
		c.ctxCancel(Public(ErrCircuit, "service control queue exhausted"))
	}
}

func (c *Circuit) AcceptStream(ctx context.Context) (net.Conn, error) {
	c.controlMu.RLock()
	state := c.service
	c.controlMu.RUnlock()
	if state == nil {
		return nil, Public(ErrCircuit, "not a service rendezvous circuit")
	}
	for {
		if state.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		select {
		case s := <-state.incoming:
			if state.ctx.Err() != nil || ctx.Err() != nil {
				_ = s.End(relay.END_REASON_DONE)
				return nil, net.ErrClosed
			}
			if !s.open() {
				_ = s.Free()
				continue
			}
			// CONNECTED and subsequent DATA must use the same FIFO; a
			// separate priority queue could let application DATA overtake it.
			if err := s.SendCell(&relay.ConnectedCell{StreamID: s.ID}); err != nil {
				_ = s.Free()
				return nil, err
			}
			return s.Conn(), nil
		case <-state.ctx.Done():
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// StopAccepting preserves accepted streams. The last stream's Close releases
// the remaining circuit; no listening socket exists at any point.
func (c *Circuit) StopAccepting() error {
	c.controlMu.Lock()
	state := c.service
	var pending []*Stream
	if state != nil {
		state.cancel()
	drain:
		for {
			select {
			case s := <-state.incoming:
				pending = append(pending, s)
			default:
				break drain
			}
		}
	}
	c.controlMu.Unlock()
	for _, s := range pending {
		_ = s.End(relay.END_REASON_DONE)
	}
	c.closeServiceIfIdle()
	return nil
}

func (c *Circuit) closeServiceIfIdle() {
	c.controlMu.RLock()
	stopped := c.service != nil && c.service.ctx.Err() != nil
	c.controlMu.RUnlock()
	if !stopped {
		return
	}
	c.streams.mu.RLock()
	idle := len(c.streams.streams) == 0
	c.streams.mu.RUnlock()
	if idle {
		_ = c.Close()
	}
}
