package gonion

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/robogg133/gonion/connection/cells"
)

func (c *Conn) writeLoop() {
	for {
		select {
		case cell := <-c.writeCall:
			if _, err := c.socket.Write(cell); err != nil {
				c.closeCh <- struct{}{}
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *Conn) readLoop() {
	for {

		header := make([]byte, 5)
		if _, err := io.ReadFull(c.socket, header); err != nil {
			c.closeCh <- struct{}{}
			return
		}
		circuitID := binary.BigEndian.Uint32(header[:4])

		var buffer bytes.Buffer
		switch header[4] {
		default:

			// Writing header to the buffer
			if _, err := buffer.Write(header); err != nil {
				c.closeCh <- struct{}{}
				return
			}

			// Writing cell body
			buf := make([]byte, cells.CELL_BODY_LEN)
			if _, err := io.ReadFull(c.socket, buf); err != nil {
				c.closeCh <- struct{}{}
				return
			}

			if _, err := buffer.Write(buf); err != nil {
				c.closeCh <- struct{}{}
				return
			}
		}

		c.mu.RLock()
		circuit := c.circuits[circuitID]
		c.mu.RUnlock()

		if circuit == nil {
			continue
		}

		select {
		case circuit.Inbound <- buffer.Bytes():
		case <-circuit.CloseCh:
			continue
		case <-c.closeCh:
			return
		}
	}
}
