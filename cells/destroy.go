package cells

import (
	"io"
)

const COMMAND_DESTROY uint8 = 4

type DestroyCell struct {
	CircuitID uint32

	Reason uint8
}

const (
	DESTROY_REASON_NONE           uint8 = iota // No reason given.
	DESTROY_REASON_PROTCOL                     // Tor protocol violation. (Note: if encounter with this reason consider creating an issue in the repo)
	DESTROY_REASON_INTERNAL                    // Internal error.
	DESTROY_REASON_REQUESTED                   // A client sent a TRUNCATE command.
	DESTROY_REASON_HIBERNATING                 // Not currently operating; trying to save bandwidth.
	DESTROY_REASON_RESOURCELIMIT               // Out of memory, sockets, or circuit IDs.
	DESTROY_REASON_CONNECTFAILED               // Unable to reach relay.
	DESTROY_REASON_OR_IDENTITY                 // Connected to relay, but its OR identity was not as expected.
	DESTROY_REASON_CHANNEL_CLOSED              // The OR connection that was carrying this circuit died.
	DESTROY_REASON_FINISHED                    // The circuit has expired for being dirty or old.
	DESTROY_REASON_TIMEOUT                     // Circuit construction took too long
	DESTROY_REASON_DESTROYED                   // The circuit was destroyed w/o client TRUNCATE
	DESTROY_REASON_NOSUCHSERVICE               // Request for unknown hidden service
)

const (
	DESTROY_REASON_NONE_MSG           string = "No reason given."                                             // No reason given.
	DESTROY_REASON_PROTCOL_MSG        string = "Tor protocol violation."                                      // Tor protocol violation. (Note: if encounter with this reason consider creating an issue in the repo)
	DESTROY_REASON_INTERNAL_MSG       string = "Internal error."                                              // Internal error.
	DESTROY_REASON_REQUESTED_MSG      string = "A client sent a TRUNCATE command."                            // A client sent a TRUNCATE command.
	DESTROY_REASON_HIBERNATING_MSG    string = "Not currently operating; trying to save bandwidth"            // Not currently operating; trying to save bandwidth.
	DESTROY_REASON_RESOURCELIMIT_MSG  string = "Out of memory, sockets, or circuit IDs."                      // Out of memory, sockets, or circuit IDs.
	DESTROY_REASON_CONNECTFAILED_MSG  string = "Unable to reach relay."                                       // Unable to reach relay.
	DESTROY_REASON_OR_IDENTITY_MSG    string = "Connected to relay, but its OR identity was not as expected." // Connected to relay, but its OR identity was not as expected.
	DESTROY_REASON_CHANNEL_CLOSED_MSG string = "The OR connection that was carrying this circuit died."       // The OR connection that was carrying this circuit died.
	DESTROY_REASON_FINISHED_MSG       string = "The circuit has expired for being dirty or old."              // The circuit has expired for being dirty or old.
	DESTROY_REASON_TIMEOUT_MSG        string = "Circuit construction took too long"                           // Circuit construction took too long
	DESTROY_REASON_DESTROYED_MSG      string = "The circuit was destroyed w/o client TRUNCATE"                // The circuit was destroyed w/o client TRUNCATE
	DESTROY_REASON_NOSUCHSERVICE_MSG  string = "Request for unknown hidden service"                           // Request for unknown hidden service
)

func (*DestroyCell) ID() uint8               { return COMMAND_DESTROY }
func (c *DestroyCell) GetCircuitID() uint32  { return c.CircuitID }
func (c *DestroyCell) SetCircuitID(n uint32) { c.CircuitID = n }

func (c *DestroyCell) Encode(w io.Writer) error {
	_, err := w.Write([]byte{c.Reason})
	return err
}

func (c *DestroyCell) Decode(r io.Reader) error {

	reason := make([]byte, 1)
	_, err := io.ReadFull(r, reason)

	c.Reason = reason[0]

	return err
}
