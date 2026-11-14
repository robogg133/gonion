package relay

import (
	"bytes"
	"fmt"
	"io"
)

const COMMAND_RELAY_END uint8 = 3

const (
	END_REASON_MISC              uint8 = iota + 1 // catch-all for unlisted reasons
	END_REASON_RESOLVEFAILED                      // couldn't look up hostname
	END_REASON_CONNECTIONREFUSED                  // remote host refused connection [*]
	END_REASON_EXITPOLICY                         // Relay refuses to connect to host or port
	END_REASON_DESTROY                            // Circuit is being destroyed
	END_REASON_DONE                               // Anonymized TCP connection was closed
	END_REASON_TIMEOUT                            // Connection timed out, or relay timed out while connecting
	END_REASON_NOROUTE                            // Routing error while attempting to contact destination
	END_REASON_HIBERNATING                        // Relay is temporarily hibernating
	END_REASON_INTERNAL                           // Internal error at the relay
	END_REASON_RESOURCELIMIT                      // Relay has no resources to fulfill request
	END_REASON_CONNRESET                          // Connection was unexpectedly reset
	END_REASON_TORPROTOCOL                        // Sent when closing conenction because of Tor protocol violations.
	END_REASON_NOTDIRECTORY                       // Client sent RELAY_BEGIN_DIR to a non-directory relay.

	// [*] Older versions of Tor also send this reason when connections are reset.
)

type RelayEndCell struct {
	StreamID uint16
	Reason   uint8
	// Payload retains the bytes that follow the reason octet (tor-spec 6.3).
	// REASON_EXITPOLICY appends an IPv4 (4 bytes) or IPv6 (16 bytes) address
	// followed by a 4-byte TTL. It is nil for the common reason-only END and
	// for an empty END, so encoding a reason-only cell is byte-identical to
	// the historical single-octet encoding.
	Payload []byte
}

func (*RelayEndCell) ID() uint8              { return COMMAND_RELAY_END }
func (c *RelayEndCell) GetStreamID() uint16  { return c.StreamID }
func (c *RelayEndCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *RelayEndCell) Encode(w io.Writer) error {
	if len(c.Payload) > RELAY_BODY_LEN-1 {
		return fmt.Errorf("relay: RELAY_END payload of %d bytes exceeds the %d-byte bound", len(c.Payload), RELAY_BODY_LEN-1)
	}
	if _, err := w.Write([]byte{c.Reason}); err != nil {
		return err
	}
	if len(c.Payload) == 0 {
		return nil
	}
	_, err := w.Write(c.Payload)
	return err
}
func (c *RelayEndCell) Decode(r io.Reader) error {
	// The whole END payload is retained, so read at most one byte beyond the
	// relay body instead of trusting the caller's reader. The frame decoder
	// already limits the reader to the declared payload length.
	body, err := io.ReadAll(io.LimitReader(r, RELAY_BODY_LEN+1))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		// tor-spec 6.3: empty RELAY_END is treated as REASON_MISC.
		c.Reason = END_REASON_MISC
		c.Payload = nil
		return nil
	}
	if len(body) > RELAY_BODY_LEN {
		return fmt.Errorf("relay: RELAY_END payload of %d bytes exceeds the %d-byte bound", len(body), RELAY_BODY_LEN)
	}
	// Unknown reasons are accepted: future Tor versions may add some.
	c.Reason = body[0]
	if len(body) == 1 {
		c.Payload = nil
		return nil
	}
	c.Payload = bytes.Clone(body[1:])
	return nil
}

// EchoedIPv4 returns the IPv4 address echoed after the reason octet of an
// EXITPOLICY RELAY_END (tor-spec 6.3: Reason | IPv4 or IPv6 | TTL), without
// the TTL. It is the structurally parsed field C Tor's
// pathbias_check_probe_response compares against the probe nonce.
//
// ok is false when the payload cannot hold a complete IPv4 address plus TTL
// (fewer than 8 bytes) or is shaped like the 16-byte IPv6 form (20 bytes or
// more). The reason octet is not inspected: callers that require EXITPOLICY
// must check Reason themselves.
func (c *RelayEndCell) EchoedIPv4() (addr [4]byte, ok bool) {
	if len(c.Payload) < 8 || len(c.Payload) >= 20 {
		return addr, false
	}
	copy(addr[:], c.Payload[:4])
	return addr, true
}

// RELAY_TRUNCATED (tor-spec 6.1, command 9) is a backward control cell
// whose payload is a single octet describing why the circuit was closed.
// The values are the DESTROY/TRUNCATED reason list in tor-spec 5.4,
// distinct from the RELAY_END reasons above.
const COMMAND_RELAY_TRUNCATED uint8 = 9

const (
	TRUNCATED_REASON_NONE           uint8 = iota // No reason given.
	TRUNCATED_REASON_PROTOCOL                    // Tor protocol violation.
	TRUNCATED_REASON_INTERNAL                    // Internal error.
	TRUNCATED_REASON_REQUESTED                   // A client sent a TRUNCATE command.
	TRUNCATED_REASON_HIBERNATING                 // Not currently operating.
	TRUNCATED_REASON_RESOURCELIMIT               // Out of memory, sockets, or circuit IDs.
	TRUNCATED_REASON_CONNECTFAILED               // Unable to reach relay.
	TRUNCATED_REASON_OR_IDENTITY                 // Relay identity was not as expected.
	TRUNCATED_REASON_CHANNEL_CLOSED              // The OR connection carrying this circuit died.
	TRUNCATED_REASON_FINISHED                    // The circuit expired for being dirty or old.
	TRUNCATED_REASON_TIMEOUT                     // Circuit construction took too long.
	TRUNCATED_REASON_DESTROYED                   // Circuit destroyed without a client TRUNCATE.
	TRUNCATED_REASON_NOSUCHSERVICE               // Request for unknown hidden service.
)

// RelayTruncatedCell is the decodable representation of RELAY_TRUNCATED,
// for later circuit-teardown integration in the circuit loop (parser side
// only). The reason is a single octet; unknown values are accepted.
type RelayTruncatedCell struct {
	StreamID uint16
	Reason   uint8
}

func (*RelayTruncatedCell) ID() uint8              { return COMMAND_RELAY_TRUNCATED }
func (c *RelayTruncatedCell) GetStreamID() uint16  { return c.StreamID }
func (c *RelayTruncatedCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *RelayTruncatedCell) Encode(w io.Writer) error {
	_, err := w.Write([]byte{c.Reason})
	return err
}
func (c *RelayTruncatedCell) Decode(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	c.Reason = b[0]
	return nil
}

// RELAY_DROP (tor-spec 6.1, command 10) is a forward-or-backward control
// dummy cell with no payload semantics: "upon receiving such a cell, the
// OR or OP must drop it".
const COMMAND_RELAY_DROP uint8 = 10

// RelayDropCell is an ignorable RELAY_DROP cell (no payload).
type RelayDropCell struct {
	StreamID uint16
}

func (*RelayDropCell) ID() uint8              { return COMMAND_RELAY_DROP }
func (c *RelayDropCell) GetStreamID() uint16  { return c.StreamID }
func (c *RelayDropCell) SetStreamID(n uint16) { c.StreamID = n }

func (*RelayDropCell) Encode(io.Writer) error { return nil }
func (*RelayDropCell) Decode(io.Reader) error { return nil }

// EndReasonString returns a short public description of a RELAY_END reason.
func EndReasonString(reason uint8) string {
	switch reason {
	case END_REASON_MISC:
		return "misc"
	case END_REASON_RESOLVEFAILED:
		return "resolve failed"
	case END_REASON_CONNECTIONREFUSED:
		return "connection refused"
	case END_REASON_EXITPOLICY:
		return "exit policy"
	case END_REASON_DESTROY:
		return "circuit destroyed"
	case END_REASON_DONE:
		return "done"
	case END_REASON_TIMEOUT:
		return "timeout"
	case END_REASON_NOROUTE:
		return "no route"
	case END_REASON_HIBERNATING:
		return "hibernating"
	case END_REASON_INTERNAL:
		return "internal"
	case END_REASON_RESOURCELIMIT:
		return "resource limit"
	case END_REASON_CONNRESET:
		return "connection reset"
	case END_REASON_TORPROTOCOL:
		return "tor protocol"
	case END_REASON_NOTDIRECTORY:
		return "not directory"
	default:
		return "unknown"
	}
}
