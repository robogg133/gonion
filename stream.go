package gonion

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/robogg133/gonion/relay"
)

type Stream struct {
	ID uint16

	circuit *Circuit

	Inbound chan relay.Cell
	CloseCh chan struct{}

	Reader *io.PipeReader
	Writer *io.PipeWriter

	SendWindow    uint16
	ReceiveWindow uint16

	State uint8

	mu        sync.RWMutex
	closeOnce sync.Once
}

const (
	STREAM_OPENING uint8 = iota
	STREAM_OPEN
	STREAM_CLOSED
)

func (c *Circuit) NewStream(kind string) (*Stream, error) {
	var suc bool

	r, w := io.Pipe()

	stream := &Stream{
		ID:            c.nextStreamID,
		circuit:       c,
		Inbound:       make(chan relay.Cell, 128),
		CloseCh:       make(chan struct{}),
		SendWindow:    500,
		ReceiveWindow: 500,
		State:         STREAM_OPENING,
		Reader:        r,
		Writer:        w,
	}

	defer func() {
		if !suc {
			c.mu.Lock()
			delete(c.streams, stream.ID)
			c.mu.Unlock()
			close(stream.CloseCh)
		}
	}()

	c.nextStreamID++

	c.mu.Lock()
	c.streams[stream.ID] = stream
	c.mu.Unlock()

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
	suc = true
	return stream, nil
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.Reader.Read(b)
}

func (s *Stream) Write(b []byte) (int, error) {
	s.mu.RLock()
	if s.State != STREAM_OPEN {
		s.mu.RUnlock()
		return 0, errors.New("stream is not open")
	}
	s.mu.RUnlock()

	var wrote int

	for len(b) > 0 {
		n := min(len(b), relay.RELAY_BODY_LEN)
		payload := b[:n]
		b = b[n:]
		wrote += n
		select {
		case s.circuit.WriteRelayCell <- &relay.DataCell{
			StreamID: s.ID,
			Payload:  payload,
		}:
			s.circuit.mu.Lock()
			s.SendWindow--
			s.circuit.SendWindow--
			s.circuit.mu.Unlock()
		case <-s.CloseCh:
			return wrote, errors.New("stream closed")
		case <-s.circuit.CloseCh:
			return wrote, errors.New("circuit closed")
		}
	}
	return wrote, nil
}

func (s *Stream) loop() {
	for {
		select {
		case <-s.CloseCh:
			s.Close()
			return
		case <-s.circuit.CloseCh:
			s.Close()
			return
		default:
		}

		s.circuit.mu.RLock()
		rcvWindow := s.ReceiveWindow
		sum := s.circuit.DigestBackwards
		s.circuit.mu.RUnlock()
		if rcvWindow%50 == 0 && rcvWindow != 500 {
			sendme := &relay.SendMeCell{
				StreamID:        s.ID,
				Version:         1,
				Sha1ForLastCell: [20]byte(sum),
			}
			select {
			case s.circuit.WriteRelayCell <- sendme:
				s.circuit.mu.Lock()
				s.ReceiveWindow += 50
				s.circuit.mu.Unlock()
			case <-s.CloseCh:
				s.Close()
				return
			case <-s.circuit.CloseCh:
				s.Close()
				return
			case <-time.After(100 * time.Millisecond):

			}
		}

		select {
		case cell := <-s.Inbound:
			s.handleCell(cell)
		case <-s.CloseCh:
			s.Close()
			return
		case <-s.circuit.CloseCh:
			s.Close()
			return
		}
	}
}

func (s *Stream) Close() {
	s.mu.Lock()
	if s.State == STREAM_CLOSED {
		s.mu.Unlock()
		return
	}
	s.State = STREAM_CLOSED
	s.mu.Unlock()

	s.closeOnce.Do(func() {
		select {
		case s.circuit.WriteRelayCell <- &relay.RelayEndCell{StreamID: s.ID}:
		case <-s.circuit.CloseCh:
		case <-time.After(100 * time.Millisecond):
		}
		close(s.CloseCh)
		s.Writer.Close()
		s.Reader.Close()
	})
}

func (s *Stream) handleCell(cell relay.Cell) {
	switch cell.ID() {
	case relay.COMMAND_DATA:
		// Update receive window
		s.circuit.mu.Lock()
		s.ReceiveWindow--
		s.circuit.ReceiveWindow--
		s.circuit.mu.Unlock()

		// Writing data to the stream pipe
		dataCell := cell.(*relay.DataCell)

		payloadCopy := make([]byte, len(dataCell.Payload))
		copy(payloadCopy, dataCell.Payload)
		_, err := s.Writer.Write(payloadCopy)
		if err != nil {
			s.Close()
		}
	case relay.COMMAND_RELAY_END:

		s.mu.Lock()
		s.State = STREAM_CLOSED
		s.mu.Unlock()

		close(s.CloseCh)
		s.Writer.Close()

	}
}
