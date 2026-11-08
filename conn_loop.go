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
			c.fail(fail(c.ctx, ErrIO, "connection read failed", err))
			return
		}
		circuitID := binary.BigEndian.Uint32(frame[:4])
		cmd := frame[4]

		circuit := c.circuits.Get(circuitID)
		if circuit == nil {
			log.Debug().Uint32("circ_id", circuitID).Uint8("cmd", cmd).Msg("cell for unknown circuit dropped")
			continue
		}

		if !circuit.reserveInbound(len(frame)) {
			log.Warn().Uint32("circ_id", circuitID).Msg("circuit inbound queue saturated")
			circuit.abortWithReason(Public(ErrCircuit, "circuit inbound queue saturated"), cells.DESTROY_REASON_RESOURCELIMIT)
			continue
		}
		select {
		case circuit.Inbound <- frame:
		case <-circuit.Ctx.Done():
			circuit.releaseInbound(len(frame))
			log.Debug().Uint32("circ_id", circuitID).Msg("drop cell: circuit done")
			continue
		case <-c.ctx.Done():
			circuit.releaseInbound(len(frame))
			return
		default:
			// A circuit that will not drain must not stall the shared read loop.
			// Tear down only that circuit (RESOURCELIMIT) and keep reading for
			// unrelated circuits. It is no longer alive, so dropping is not a
			// silent END loss on a live circuit.
			circuit.releaseInbound(len(frame))
			log.Warn().Uint32("circ_id", circuitID).Msg("circuit inbound queue saturated")
			circuit.abortWithReason(Public(ErrCircuit, "circuit inbound queue saturated"), cells.DESTROY_REASON_RESOURCELIMIT)
			continue
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
				c.fail(fail(c.ctx, ErrIO, "connection write failed", err))
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}
