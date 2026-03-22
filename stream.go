package gonion2

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"git.servidordomal.fun/robogg133/gonion-rewrite/pkg/cells/relay"
)

type Stream struct {
	ID uint16

	circuit *Circuit

	Inbound chan relay.Cell
	CloseCh chan struct{}

	Reader *io.PipeReader
	writer *io.PipeWriter

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

	r, w := io.Pipe()

	stream := &Stream{
		ID:            c.nextStreamID,
		circuit:       c,
		Inbound:       make(chan relay.Cell, 512),
		CloseCh:       make(chan struct{}),
		receiveSendMe: make(chan struct{}, 1),

		SendWindow: &window{
			v: 500,
		},
		ReceiveWindow: &window{
			v: 500,
		},

		State: STREAM_OPENING,

		writer: w,
		Reader: r,
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
	suc = true
	return stream, nil
}

func (s *Stream) loop() {
	for {
		// Check receive window and send SENDME if needed
		s.ReceiveWindow.mu.Lock()
		if s.ReceiveWindow.v%50 == 0 && s.ReceiveWindow.v != 500 {
			cell := &relay.SendMeCell{
				StreamID:        s.ID,
				Version:         s.circuit.SendMeVersion,
				Sha1ForLastCell: [20]byte(s.circuit.Backwards.Sum()),
			}
			s.SendCell(cell)
			s.ReceiveWindow.v += 50
		}
		s.ReceiveWindow.mu.Unlock()

		select {
		case cell, ok := <-s.Inbound:
			if !ok {
				return
			}
			s.handleCell(cell)
		case <-s.CloseCh:
			return
		}
	}
}

func (s *Stream) handleCell(cell relay.Cell) {
	switch cell.ID() {
	case relay.COMMAND_DATA:
		s.ReceiveWindow.Subtract(1)
		s.circuit.ReceiveWindow.Subtract(1)
		if _, err := io.Copy(s.writer, bytes.NewReader(cell.(*relay.DataCell).Payload)); err != nil {
			s.Close()
			return
		}
	case relay.COMMAND_SENDME:
		// Non-blocking send: if nobody is waiting it's fine to drop.
		select {
		case s.receiveSendMe <- struct{}{}:
		default:
		}
	case relay.COMMAND_RELAY_END:
		// Acknowledge the stream close by sending our own RELAY_END back.
		// Without this, some relays send DESTROY with "protocol violation"
		// because the stream teardown was half-closed from their perspective.
		s.Close()
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
	s.SendWindow.mu.Lock()
	defer s.SendWindow.mu.Unlock()

	cell.SetStreamID(s.ID)

	if s.SendWindow.v%50 == 0 && s.SendWindow.v != 500 {
		select {
		case <-s.receiveSendMe:
			s.SendWindow.v += 50
		case <-s.CloseCh:
			return errors.New("stream closed")
		}
	}

	select {
	case s.circuit.WriteRelayCell <- cell:
	case <-s.CloseCh:
		return errors.New("stream closed")
	}

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
		err = s.writer.Close()
	})
	return err
}
