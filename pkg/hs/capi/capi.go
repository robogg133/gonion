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

// PathBiasProbeResult is the outcome of a path-spec §7.2 END-echo usage
// probe. The probe is a RELAY_BEGIN to 0.a.b.c:25 carrying a random 24-bit
// nonce; the exit rejects it with REASON_EXITPOLICY and echoes the address,
// matching C Tor's pathbias_send_usable_probe/pathbias_check_probe_response.
type PathBiasProbeResult uint8

const (
	// PathBiasProbeUnsent means no probe reached the circuit, so the result
	// carries no reachability signal. Examples: the circuit died before the
	// BEGIN was written, no StreamID was left, or the caller's context was
	// already done. The zero value is deliberately "nothing was measured".
	PathBiasProbeUnsent PathBiasProbeResult = iota
	// PathBiasProbeMatched means the exit echoed the probe's nonce in a
	// REASON_EXITPOLICY RELAY_END on the probe's reserved StreamID.
	PathBiasProbeMatched
	// PathBiasProbeMismatched means the probe was sent but not confirmed: a
	// RELAY_END with another reason or nonce, an unexpected relay cell on the
	// probe StreamID, or a wait interrupted by cancellation, deadline, or
	// circuit loss. A sent probe is never reported as a success without the
	// nonce echo.
	PathBiasProbeMismatched
)

func (r PathBiasProbeResult) String() string {
	switch r {
	case PathBiasProbeUnsent:
		return "unsent"
	case PathBiasProbeMatched:
		return "matched"
	case PathBiasProbeMismatched:
		return "mismatched"
	default:
		return "unknown"
	}
}

// PathBiasProber is the optional path-bias probe capability. It is
// deliberately not part of Circ: a circuit may be usable without exposing it,
// and callers must type-assert. PathBiasProbe reserves a fresh never-reused
// StreamID without creating a Stream, sends the probe to the circuit's last
// hop, and returns after the echo, an interruption, or a send failure. Reuse
// of the probe StreamID is impossible, so a normal Stream never receives the
// probe's RELAY_END. The caller owns circuit lifetime; C Tor closes the
// circuit after the probe is answered.
type PathBiasProber interface {
	PathBiasProbe(ctx context.Context) (PathBiasProbeResult, error)
}

// StreamFailureReasoner is the optional capability exposing the relay END
// reason received in response to the most recent failed stream attachment
// attempt (path-spec §7.2); zero means no failed attempt was recorded.
// Callers combine it with PathBiasProber: a bare usage attempt whose stream
// attempt failed with DESTROY, TORPROTOCOL, or INTERNAL must not be probed
// and is declared a usage failure directly. Every other reason, and the
// absence of a recorded reason, keeps the bare attempt eligible for the
// close-time probe. The base Circ interface is deliberately unchanged.
type StreamFailureReasoner interface {
	StreamFailureReason() uint8
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

// GuardProvider supplies a caller-authenticated fixed first hop (a bridge).
// Nil means ordinary guard selection. Errors must not trigger a public fallback.
type GuardProvider interface {
	CircuitGuard(context.Context) (*common.RouterStatus, error)
}

func CircuitGuard(ctx context.Context, builder CircuitBuilder) (*common.RouterStatus, error) {
	if b, ok := builder.(GuardProvider); ok {
		return b.CircuitGuard(ctx)
	}
	return nil, nil
}

// ContextCircuitBuilder is required by services so renewal and shutdown can
// interrupt circuit construction without cancelling unrelated connections.
type ContextCircuitBuilder interface {
	CircuitBuilder
	BuildPathContext(ctx context.Context, id uint32, relays []*common.RouterStatus) (Circ, error)
}
