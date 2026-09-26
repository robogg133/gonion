// Package capi defines the minimal circuit/stream/builder interfaces the
// hidden-service client needs, decoupled from the concrete *gonion.Circuit so
// that pkg/hs does not import pkg/gonion (which already imports pkg/hs).
// Adapters for *gonion.Circuit / *gonion.Conn live in pkg/gonion and pkg/embed.
package capi

import (
	"context"
	"crypto/ed25519"
	"net"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
)

// Circ is the subset of a Tor circuit used by the hidden-service client.
type Circ interface {
	HopCount() int
	// Ctx returns the circuit's lifecycle context; closed when the circuit dies.
	Ctx() context.Context
	// NewStream opens a stream to target at hop hopDest and returns it.
	NewStream(target string, hopDest int) (Stream, error)
	// SendHSControl relays a circuit-level HS control cell (StreamID == 0).
	SendHSControl(cell relay.Cell) error
	// SetHSControl registers the channel that receives HS control cells.
	SetHSControl(ch chan relay.Cell)
	// RecvHSControl blocks until an HS control cell arrives or ctx ends.
	RecvHSControl(ctx context.Context) (relay.Cell, error)
	// AppendE2EHop attaches an HS-v3 client hop: AES-256-CTR, SHA3-256,
	// with four 32-byte inputs. It must not use ordinary AES-128/SHA-1 hop
	// state. Send and receive digest/window state must be independent of
	// the rendezvous relay's state.
	AppendE2EHop(Kf, Kb, Df, Db []byte) error
	// Close tears the circuit down.
	Close() error
}

// ServiceCirc adds the service-side operations. The adapter owns the incoming
// stream queue and the circuit nonce; applications cannot replace either.
type ServiceCirc interface {
	Circ
	EstablishIntro(auth ed25519.PrivateKey) error
	JoinRendezvous(cookie [20]byte, reply, Kf, Kb, Df, Db []byte, address string) error
	AcceptStream(ctx context.Context) (net.Conn, error)
	// StopAccepting rejects new/pending streams without closing accepted ones.
	StopAccepting() error
}

// Stream is the subset of a stream needed to fetch descriptors and send
// introduce cells.
type Stream interface {
	SendCell(cell relay.Cell) error
	// Recv blocks for the next stream-level control cell (e.g. INTRODUCE_ACK)
	// or returns on context cancellation.
	Recv(ctx context.Context) (relay.Cell, error)
	Conn() net.Conn
	Free() error
}

// CircuitBuilder builds circuits (implemented by *gonion.Conn in pkg/embed).
type CircuitBuilder interface {
	BuildPath(id uint32, relays []*common.RouterStatus) (Circ, error)
}

// ContextCircuitBuilder is required by services so renewal and shutdown can
// interrupt circuit construction without cancelling unrelated connections.
type ContextCircuitBuilder interface {
	CircuitBuilder
	BuildPathContext(ctx context.Context, id uint32, relays []*common.RouterStatus) (Circ, error)
}
