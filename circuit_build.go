package gonion

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/handshakes"
	"github.com/robogg133/gonion/pkg/lspec"
)

// NewCircuitTo creates a 1-hop ntor circuit to guard.
func (c *Conn) NewCircuitTo(id uint32, guard *common.RouterStatus) (*Circuit, error) {
	hs, err := newNTorHandshake(guard)
	if err != nil {
		return nil, fail(c.ctx, ErrCircuit, "build ntor handshake failed", err)
	}
	return c.NewCircuit(id, handshakes.HTYPE_NTOR, hs)
}

// ExtendTo extends the circuit one hop toward relay via EXTEND2 + ntor.
func (c *Circuit) ExtendTo(relay *common.RouterStatus) error {
	lspecs, err := linkSpecsFor(relay)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "build link specs failed", err)
	}
	hs, err := newNTorHandshake(relay)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "build ntor handshake failed", err)
	}
	return c.Extend(lspecs, handshakes.HTYPE_NTOR, hs)
}

// BuildPath creates the onion path for relays[0]=guard … relays[n-1]=exit.
// The circuit must be empty; hop 0 is created, the rest are extended.
func (c *Conn) BuildPath(id uint32, relays []*common.RouterStatus) (*Circuit, error) {
	if len(relays) == 0 {
		return nil, Public(ErrCircuit, "empty path")
	}
	circ, err := c.NewCircuitTo(id, relays[0])
	if err != nil {
		return nil, err
	}
	for i, r := range relays[1:] {
		if err := circ.ExtendTo(r); err != nil {
			_ = circ.Close()
			return nil, failf(circ.Ctx, ErrExtend, err, "extend hop %d failed", i+1)
		}
	}
	return circ, nil
}

// Dial opens a stream to addr (host:port) through the circuit exit hop.
func (c *Circuit) Dial(addr string) (net.Conn, error) {
	if c.hops.Len() == 0 {
		return nil, Public(ErrCircuit, "empty circuit")
	}
	stream, err := c.NewStream(addr, c.hops.Len()-1)
	if err != nil {
		return nil, err
	}
	return stream.Conn(), nil
}

func newNTorHandshake(r *common.RouterStatus) (*handshakes.Client_NTorHandshake, error) {
	if r == nil {
		return nil, Public(ErrCircuit, "nil relay")
	}
	if r.NTorOnionKey == nil {
		return nil, Publicf(ErrCircuit, "relay %s missing ntor key", r.Nickname)
	}
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &handshakes.Client_NTorHandshake{
		NodeID:     r.NodeID,
		KeyID:      r.NTorOnionKey,
		PrivateKey: sk,
		PublicKey:  sk.PublicKey(),
	}, nil
}

func linkSpecsFor(r *common.RouterStatus) ([]lspec.Lspec, error) {
	if r.Ipv4Addr == "" || r.ORPort == 0 {
		return nil, Publicf(ErrExtend, "relay %s missing OR address", r.Nickname)
	}
	ip, err := lspec.NewLespecFromIPText(fmt.Sprintf("%s:%d", r.Ipv4Addr, r.ORPort))
	if err != nil {
		return nil, err
	}
	if len(r.IdEd25519) != 32 {
		return nil, Publicf(ErrExtend, "relay %s missing ed25519 id", r.Nickname)
	}
	return []lspec.Lspec{
		ip,
		lspec.NewNodeID(r.NodeID),
		lspec.NewEd25519ID(r.IdEd25519),
	}, nil
}
