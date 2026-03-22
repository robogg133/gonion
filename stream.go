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
		CloseCh:       make(chan struct{}, 1),
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
			close(stream.CloseCh)
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

		s.ReceiveWindow.mu.Lock()
		if s.ReceiveWindow.v%50 == 0 && s.ReceiveWindow.v != 500 {

			cell := &relay.SendMeCell{
				StreamID:        0,
				Version:         1,
				Sha1ForLastCell: [20]byte(s.circuit.Backwards.Sum()),
			}

			s.SendCell(cell)
			s.ReceiveWindow.v += 50

		}
		s.ReceiveWindow.mu.Unlock()

		select {
		case cell := <-s.Inbound:
			go s.handleCell(cell)
		case <-s.CloseCh:
			s.Close()
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
		s.receiveSendMe <- struct{}{}
	case relay.COMMAND_RELAY_END:
		s.Close()
	}
}

func (s *Stream) Write(b []byte) (n int, err error) {
	if s.State != STREAM_OPEN {
		s.mu.RUnlock()
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
		<-s.receiveSendMe
		s.SendWindow.v += 50
	}

	select {
	case s.circuit.WriteRelayCell <- cell:
	case <-s.CloseCh:
		return errors.New("stream closed")
	}

	return nil
}

func (s *Stream) Close() error {

	s.State = STREAM_CLOSED

	close(s.CloseCh)
	close(s.receiveSendMe)
	close(s.Inbound)

	return s.writer.Close()
}
