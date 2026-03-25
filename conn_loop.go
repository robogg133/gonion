package gonion2

import (
	"bytes"
	"encoding/binary"
	"io"

	cells "git.servidordomal.fun/robogg133/gonion/pkg/cells/base"
)

func (c *Conn) readLoop() {
	for {

		header := make([]byte, 5)
		if _, err := io.ReadFull(c.socket, header); err != nil {
			c.closeError(err.Error())
			return
		}
		circuitID := binary.BigEndian.Uint32(header[:4])

		var buffer bytes.Buffer
		switch header[4] {
		default:

			// Writing header to the buffer
			if _, err := buffer.Write(header); err != nil {
				c.closeError(err.Error())
				return
			}

			// Writing cell body
			buf := make([]byte, cells.CELL_BODY_LEN)
			if _, err := io.ReadFull(c.socket, buf); err != nil {
				c.closeError(err.Error())
				return
			}

			if _, err := buffer.Write(buf); err != nil {
				c.closeError(err.Error())
				return
			}
		}

		circuit := c.circuits.Get(circuitID)

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

func (c *Conn) writeLoop() {
	for {
		select {
		case cell := <-c.writeCall:
			if _, err := c.socket.Write(cell); err != nil {

				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *Conn) closeError(s string) error {
	c.closeCh <- s
	return nil
}
