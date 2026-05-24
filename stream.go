package gonion

import (
	"errors"
	"io"
	"sync"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/smallnest/ringbuffer"
)

type Stream struct {
	ID uint16

	circuit *Circuit

	InboundControl chan relay.Cell
	CloseCh        chan struct{}

	outbound chan relay.Cell

	Reader io.ReadCloser
	buffer *ringbuffer.RingBuffer

	SendWindow    *window
	ReceiveWindow *window

	State uint8

	mu        sync.RWMutex
	closeOnce sync.Once

	receiveSendMe chan struct{}
}

const (
	STREAM_OPENING uint8 = iota
	STREAM_OPEN
	STREAM_CLOSED
)

func (c *Circuit) NewStream(kind string) (*Stream, error) {
	var suc bool

	// 128KB buffer
	buffer := ringbuffer.New(128 << 10).SetBlocking(true)

	stream := &Stream{
		ID:             c.nextStreamID,
		circuit:        c,
		InboundControl: make(chan relay.Cell, 512),
		outbound:       make(chan relay.Cell, 512),
		CloseCh:        make(chan struct{}),
		receiveSendMe:  make(chan struct{}, 1),

		SendWindow: &window{
			v: 500,
		},
		ReceiveWindow: &window{
			v: 500,
		},

		State: STREAM_OPENING,

		buffer: buffer,
		Reader: buffer.ReadCloser(),
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
	go stream.loop()
	go stream.sendController()
	suc = true
	return stream, nil
}

func (s *Stream) loop() {
	for {
		select {
		case cell, ok := <-s.InboundControl:
			if !ok {
				return
			}

			switch cell.ID() {
			case relay.COMMAND_SENDME:
				s.receiveSendMe <- struct{}{}
			case relay.COMMAND_RELAY_END:
				s.Close()
			}

		case <-s.CloseCh:
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
				s.SendWindow.mu.RLock()
				needwait := s.SendWindow.v%50 == 0 && s.SendWindow.v != 500
				s.SendWindow.mu.RUnlock()

				if needwait {
					select {
					case <-s.receiveSendMe:
						s.SendWindow.Add(50)
					case <-s.CloseCh:
						return
					}
				}
			}
			select {
			case s.circuit.WriteRelayCell <- cell:
			case <-s.CloseCh:
				return
			}
		case <-s.CloseCh:
			return
		}
	}
}

// WriteAsync will not lock until the receive of a send_me and will put the packet in a line

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
	case <-s.CloseCh:
		return errors.New("stream closed")
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

		close(s.CloseCh)
		// Drain and close receiveSendMe so any blocked SendCell unblocks.
		close(s.receiveSendMe)
		s.buffer.CloseWriter()
	})
	return err
}

func (s *Stream) writeDataCell(cell *relay.DataCell) error {
	s.ReceiveWindow.Subtract(1)
	s.circuit.ReceiveWindow.Subtract(1)

	if _, err := s.buffer.Write(cell.Payload); err != nil {
		return err
	}

	if s.ReceiveWindow.Get()%50 == 0 {
		s.SendCell(&relay.SendMeCell{
			StreamID:        s.ID,
			Version:         s.circuit.SendMeVersion,
			Sha1ForLastCell: s.circuit.Backwards.GetLastSumDataCell(),
		})
		s.ReceiveWindow.Add(50)
	}

	return nil
}
