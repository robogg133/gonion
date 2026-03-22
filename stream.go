package gonion2

import (
	"bytes"
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
	Writer *io.PipeWriter

	SendWindow    *window
	ReceiveWindow *window

	State uint8

	mu        sync.RWMutex
	closeOnce sync.Once

	receivedWindow chan struct{}
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
		ID:      c.nextStreamID,
		circuit: c,
		Inbound: make(chan relay.Cell, 512),
		CloseCh: make(chan struct{}),

		SendWindow: &window{
			v: 500,
		},
		ReceiveWindow: &window{
			v: 500,
		},

		State: STREAM_OPENING,

		Writer: w,
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

			select {
			case s.circuit.WriteRelayCell <- cell:
				s.ReceiveWindow.Add(50)
			case <-s.CloseCh:
				s.Close()
				return
			}
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

		if _, err := io.Copy(s.Writer, bytes.NewReader(cell.(*relay.DataCell).Payload)); err != nil {
			s.Close()
			return
		}
	case relay.COMMAND_SENDME:
		s.receivedWindow <- struct{}{}
	case relay.COMMAND_RELAY_END:
		s.Close()
	}
}

func (s *Stream) Close() error {

	s.State = STREAM_CLOSED

	close(s.CloseCh)
	close(s.receivedWindow)
	close(s.Inbound)

	return s.Writer.Close()
}
