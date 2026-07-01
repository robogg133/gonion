package gonion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

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

	myHopDestination uint8
	circuit          *Circuit

	InboundControl chan relay.Cell
	Ctx            context.Context
	ctxCancel      context.CancelCauseFunc

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

func (c *Circuit) NewStream(kind string, hopDest uint8) (*Stream, error) {
	var suc bool
	ctx, ctxCancel := context.WithCancelCause(c.Ctx)

	buffer := ringbuffer.New(STREAM_BUFFER_SIZE).SetBlocking(true)

	stream := &Stream{
		ID:             c.nextStreamID,
		circuit:        c,
		InboundControl: make(chan relay.Cell, 512),
		outbound:       make(chan relay.Cell, 2048),
		Ctx:            ctx,
		ctxCancel:      ctxCancel,
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
			stream.Close()
		}
	}()

	c.nextStreamID++

	c.streams.Set(stream.ID, stream)

	switch kind {
	case "dir":
		if err := stream.beginDir(); err != nil {
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
				select {
				case s.receiveSendMe <- struct{}{}:
				default:
				}
			case relay.COMMAND_RELAY_END:
				fmt.Println("RELAY END")
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
				s.SendWindow.Subtract(1)
				if s.SendWindow.Check() {
					s.SendWindow.SetDigest(cell.(*relay.DataCell).Digest())
				}

				if s.SendWindow.Get() == 0 {
					select {
					case <-s.receiveSendMe:
						s.SendWindow.Increase()
					case <-s.Ctx.Done():
						return
					}
				}
			}
			select {
			case s.circuit.WriteRelayCell <- struct {
				relay.Cell
				uint8
			}{Cell: cell, uint8: s.myHopDestination}:
			case <-s.Ctx.Done():
				return
			}
		case <-s.Ctx.Done():
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
		return s.Ctx.Err()
	}
}

func (s *Stream) Free() error {
	if s.State != STREAM_CLOSED {
		if err := s.Close(); err != nil {
			return err
		}
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

		s.ctxCancel(errors.New("requested close"))
		// Drain and close receiveSendMe so any blocked SendCell unblocks.
		close(s.receiveSendMe)
		s.buffer.CloseWriter()
	})
	return err
}

func (s *Stream) writeDataCell(cell *relay.DataCell) error {
	s.ReceiveWindow.Subtract(1)
	if s.ReceiveWindow.Check() {
		s.ReceiveWindow.SetDigest(cell.Digest())
	}

	if _, err := s.buffer.Write(cell.Payload); err != nil {
		return err
	}

	return nil
}
