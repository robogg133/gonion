package gonion

import (
	"bytes"
	"encoding/binary"
	"io"

	cells "github.com/robogg133/gonion/pkg/cells/base"
)

func (c *Conn) readLoop() {
	for {

		header := make([]byte, 5)
		if _, err := io.ReadFull(c.socket, header); err != nil {
			c.ctxCancel(err)
			return
		}
		circuitID := binary.BigEndian.Uint32(header[:4])

		var buffer bytes.Buffer
		switch header[4] {
		default:

			// Writing header to the buffer
			if _, err := buffer.Write(header); err != nil {
				c.ctxCancel(err)
				return
			}

			// Writing cell body
			buf := make([]byte, cells.CELL_BODY_LEN)
			if _, err := io.ReadFull(c.socket, buf); err != nil {
				c.ctxCancel(err)
				return
			}

			if _, err := buffer.Write(buf); err != nil {
				c.ctxCancel(err)
				return
			}
		}

		circuit := c.circuits.Get(circuitID)

		if circuit == nil {
			continue
		}

		select {
		case circuit.Inbound <- buffer.Bytes():
		case <-circuit.Ctx.Done():
			continue
		case <-c.ctx.Done():
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
		case <-c.ctx.Done():
			return
		}
	}
}
