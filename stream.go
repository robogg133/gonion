package gonion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/internal/window"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/smallnest/ringbuffer"
)

const (
	STREAM_OPENING uint8 = iota
	STREAM_OPEN
	STREAM_CLOSED
)

const (
	STREAM_BUFFER_SIZE            = 256 << 10 // 256KB
	STREAM_SENDME_AMMOUNT_TRIGGER = 5 << 10   // 5KB
)

type Stream struct {
	ID uint16

	myHopDestination int
	circuit          *Circuit
	addr             net.Addr

	InboundControl chan relay.Cell
	Ctx            context.Context
	freeCtx        context.Context
	ctxCancel      context.CancelCauseFunc
	freeCtxCancel  context.CancelCauseFunc

	outbound chan relay.Cell

	Reader io.ReadCloser
	buffer *ringbuffer.RingBuffer

	SendWindow    *window.Window
	ReceiveWindow *window.Window

	State uint8

	mu        sync.RWMutex
	closeOnce sync.Once

	receiveSendMe chan struct{}
}

func (c *Circuit) NewStream(target string, hopDest int) (*Stream, error) {
	var suc bool
	freeCtx, freeCtxCancel := context.WithCancelCause(c.Ctx)
	ctx, ctxCancel := context.WithCancelCause(freeCtx)

	buffer := ringbuffer.New(STREAM_BUFFER_SIZE).SetBlocking(true).WithNoCloseOnTimeout()

	stream := &Stream{
		ID:             c.nextStreamID,
		circuit:        c,
		InboundControl: make(chan relay.Cell, 512),
		outbound:       make(chan relay.Cell, 2048),
		Ctx:            ctx,
		ctxCancel:      ctxCancel,
		freeCtx:        freeCtx,
		freeCtxCancel:  freeCtxCancel,
		receiveSendMe:  make(chan struct{}, 1),

		SendWindow:       window.NewWindow(500, 50),
		ReceiveWindow:    window.NewWindow(500, 50),
		myHopDestination: hopDest,

		State: STREAM_OPENING,

		buffer: buffer,
	}
	stream.Reader = &readCloserWrapper{
		buff:   buffer,
		stream: stream,
	}

	defer func() {
		if !suc {
			c.streams.Delete(stream.ID)
			stream.Free()
		}
	}()

	c.nextStreamID++

	c.streams.Set(stream.ID, stream)

	switch target {
	case "dir":
		stream.addr = shared.NewAddr("tcp", "")
		if err := stream.beginDir(); err != nil {
			return nil, err
		}
	default:
		stream.addr = shared.NewAddr("tcp", target)
		if err := stream.begin(target); err != nil {
			return nil, err
		}
	}
	stream.mu.Lock()
	stream.State = STREAM_OPEN
	stream.mu.Unlock()
	go stream.controlLoop()
	go stream.sendController()
	suc = true
	return stream, nil
}

func (s *Stream) controlLoop() {
	for {
		select {
		case cell, ok := <-s.InboundControl:
			if !ok {
				return
			}
			// SWITCH for controll cells
			switch cell.ID() {
			case relay.COMMAND_SENDME:
				sendme := cell.(*relay.SendMeCell)
				if err := verifySendMe(sendme, s.circuit.SendMeVersion, s.SendWindow); err != nil {
					s.circuit.ctxCancel(fmt.Errorf("(stream %d): %s", s.ID, err.Error()))
					s.Free()
				}

				select {
				case s.receiveSendMe <- struct{}{}:
				default:
				}
			case relay.COMMAND_RELAY_END:
				s.Close()
			}

		case <-s.Ctx.Done():
			return
		}
	}
}

// sendController Controls sendWindow and can line up relay cells
func (s *Stream) sendController() {
	for {
		select {
		case cell, ok := <-s.outbound:
			if !ok {
				return
			}

			if cell.ID() == relay.COMMAND_DATA {
				s.SendWindow.SetDigest(cell.(*relay.DataCell).Digest())
				s.SendWindow.Subtract(1)

				if s.SendWindow.IsZero() {
					select {
					case <-s.receiveSendMe:
						s.SendWindow.Increase()
					case <-s.Ctx.Done():
						return
					}
				}

			}
			select {
			case s.circuit.WriteRelayCell <- RelayOut{Cell: cell, Dst: s.myHopDestination}:
			case <-s.Ctx.Done():
				s.Close()
				return
			}
		case <-s.Ctx.Done():
			s.Close()
			return
		}
	}
}

func (s *Stream) Write(b []byte) (n int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.State != STREAM_OPEN {
		return 0, errors.New("stream closed")
	}
	var wrote int

	for len(b) > 0 {
		n := min(len(b), relay.RELAY_BODY_LEN)
		payload := b[:n]
		b = b[n:]
		wrote += n

		err := s.SendCell(&relay.DataCell{
			StreamID: s.ID,
			Payload:  payload,
		})
		if err != nil {
			return wrote, err
		}
	}
	return wrote, nil
}

func (s *Stream) SendCell(cell relay.Cell) error {
	if s.State == STREAM_CLOSED {
		return errors.New("stream closed")
	}

	cell.SetStreamID(s.ID)
	select {
	case s.outbound <- cell:
		return nil
	case <-s.Ctx.Done():
		s.Close()
		return context.Cause(s.Ctx)
	}
}

func (s *Stream) End(reason uint8) error {
	if err := s.SendCell(&relay.RelayEndCell{Reason: reason}); err != nil {
		return err
	}
	return s.Free()
}
func (s *Stream) Free() error {
	if s.State != STREAM_CLOSED {
		if err := s.Close(); err != nil {
			return err
		}
	}
	if s.freeCtx.Err() == nil {
		s.freeCtxCancel(errors.New("requested free"))
	}

	if err := s.Reader.Close(); err != nil {
		return err
	}
	s.circuit.streams.Delete(s.ID)
	return nil
}

func (s *Stream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.State = STREAM_CLOSED
		s.mu.Unlock()

		if s.Ctx.Err() == nil {
			s.ctxCancel(errors.New("requested close"))
		}
		if s.freeCtx.Err() != nil {
			defer s.Free()
		}

		close(s.ReceiveWindow.Trigged)
		close(s.SendWindow.Trigged)
		close(s.receiveSendMe)
		s.buffer.CloseWriter()
	})
	return err
}

func (s *Stream) writeDataCell(cell *relay.DataCell) error {
	s.ReceiveWindow.SetDigest(cell.Digest())
	s.ReceiveWindow.Subtract(1)

	if _, err := s.buffer.Write(cell.Payload); err != nil {
		return err
	}

	return nil
}

func (s *Stream) Conn() net.Conn {
	return &netWrapper{s: s}
}

type netWrapper struct {
	s *Stream
}

func (w *netWrapper) Write(p []byte) (int, error) {
	return w.s.Write(p)
}

func (w *netWrapper) Read(p []byte) (int, error) {
	return w.s.Reader.Read(p)
}

func (w *netWrapper) SetWriteDeadline(t time.Time) error {
	w.s.buffer.WithWriteTimeout(time.Until(t))
	return nil
}

func (w *netWrapper) SetDeadline(t time.Time) error {
	w.s.buffer.WithTimeout(time.Until(t))
	return nil
}

func (w *netWrapper) SetReadDeadline(t time.Time) error {
	w.s.buffer.WithReadTimeout(time.Until(t))
	return nil
}

func (w *netWrapper) LocalAddr() net.Addr {
	return w.s.circuit.conn.socket.LocalAddr()
}
func (w *netWrapper) RemoteAddr() net.Addr {
	return w.s.addr
}

func (w *netWrapper) Close() error {
	return w.s.End(relay.END_REASON_MISC)
}
