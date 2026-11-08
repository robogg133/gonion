package relay

import "io"

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
}

func (*RelayEndCell) ID() uint8              { return COMMAND_RELAY_END }
func (c *RelayEndCell) GetStreamID() uint16  { return c.StreamID }
func (c *RelayEndCell) SetStreamID(n uint16) { c.StreamID = n }

func (c *RelayEndCell) Encode(w io.Writer) error {
	_, err := w.Write([]byte{c.Reason})
	return err
}
func (c *RelayEndCell) Decode(r io.Reader) error {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	if err == io.EOF {
		// tor-spec 6.3: empty RELAY_END is treated as REASON_MISC.
		c.Reason = END_REASON_MISC
		return nil
	}
	if err != nil {
		return err
	}
	// Unknown reasons are accepted: future Tor versions may add some.
	c.Reason = b[0]
	return nil
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
