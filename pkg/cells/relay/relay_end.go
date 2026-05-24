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
	b := make([]byte, 1)
	_, err := r.Read(b)
	c.Reason = b[0]
	return err
}
