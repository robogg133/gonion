package gonion

import (
	"bytes"
	"encoding/binary"
	"io"

	cells "github.com/robogg133/gonion/pkg/cells/base"
)

func (c *Conn) readLoop() {
	log := logger(c.ctx)
	log.Debug().Msg("read loop started")
	defer log.Debug().Msg("read loop stopped")

	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(c.socket, header); err != nil {
			log.Error().Err(err).Msg("read cell header failed")
			c.ctxCancel(fail(c.ctx, ErrIO, "connection read failed", err))
			return
		}
		circuitID := binary.BigEndian.Uint32(header[:4])
		cmd := header[4]

		var buffer bytes.Buffer
		if _, err := buffer.Write(header); err != nil {
			log.Error().Err(err).Msg("buffer header failed")
			c.ctxCancel(fail(c.ctx, ErrIO, "connection read failed", err))
			return
		}

		buf := make([]byte, cells.CELL_BODY_LEN)
		if _, err := io.ReadFull(c.socket, buf); err != nil {
			log.Error().Err(err).Uint8("cmd", cmd).Msg("read cell body failed")
			c.ctxCancel(fail(c.ctx, ErrIO, "connection read failed", err))
			return
		}
		if _, err := buffer.Write(buf); err != nil {
			log.Error().Err(err).Msg("buffer body failed")
			c.ctxCancel(fail(c.ctx, ErrIO, "connection read failed", err))
			return
		}

		circuit := c.circuits.Get(circuitID)
		if circuit == nil {
			log.Debug().Uint32("circ_id", circuitID).Uint8("cmd", cmd).Msg("cell for unknown circuit dropped")
			continue
		}

		select {
		case circuit.Inbound <- buffer.Bytes():
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
			if _, err := c.socket.Write(cell); err != nil {
				log.Error().Err(err).Int("len", len(cell)).Msg("write cell failed")
				c.ctxCancel(fail(c.ctx, ErrIO, "connection write failed", err))
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}
