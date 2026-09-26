package gonion

import (
	"encoding/binary"
	"io"

	cells "github.com/robogg133/gonion/pkg/cells/base"
)

func (c *Conn) readLoop() {
	log := logger(c.ctx)
	log.Debug().Msg("read loop started")
	defer log.Debug().Msg("read loop stopped")

	for {
		frame, err := cells.ReadFrame(c.socket, c.ProtcolVersion)
		if err != nil {
			log.Error().Err(err).Msg("read cell header failed")
			c.ctxCancel(fail(c.ctx, ErrIO, "connection read failed", err))
			return
		}
		circuitID := binary.BigEndian.Uint32(frame[:4])
		cmd := frame[4]

		circuit := c.circuits.Get(circuitID)
		if circuit == nil {
			log.Debug().Uint32("circ_id", circuitID).Uint8("cmd", cmd).Msg("cell for unknown circuit dropped")
			continue
		}

		select {
		case circuit.Inbound <- frame:
		case <-circuit.Ctx.Done():
			log.Debug().Uint32("circ_id", circuitID).Msg("drop cell: circuit done")
			continue
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Conn) writeLoop() {
	log := logger(c.ctx)
	log.Debug().Msg("write loop started")
	defer log.Debug().Msg("write loop stopped")

	for {
		select {
		case cell := <-c.writeCall:
			n, err := c.socket.Write(cell.data)
			if err == nil && n != len(cell.data) {
				err = io.ErrShortWrite
			}
			cell.done <- err
			if err != nil {
				log.Error().Err(err).Int("len", len(cell.data)).Msg("write cell failed")
				c.ctxCancel(fail(c.ctx, ErrIO, "connection write failed", err))
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}
