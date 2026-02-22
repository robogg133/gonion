package gonion

import (
	"errors"
	"fmt"
	"io"

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
}

const (
	STREAM_OPENING uint8 = iota
	STREAM_OPEN
	STREAM_CLOSED
)

func (c *Circuit) NewStream(kind string) (*Stream, error) {
	var suc bool

	fmt.Println("=> Creating pipe")
	r, w := io.Pipe()
	fmt.Println("=> Pipe done")

	fmt.Println("=> Instantiating the struct")
	stream := &Stream{
		ID:            c.nextStreamID,
		circuit:       c,
		Inbound:       make(chan relay.Cell, 32),
		CloseCh:       make(chan struct{}),
		SendWindow:    500,
		ReceiveWindow: 500,
		State:         STREAM_OPENING,

		Reader: r,
		Writer: w,
	}
	fmt.Println("=> Instantiated the struct")

	defer func() {
		if !suc {
			c.mu.Lock()
			delete(c.streams, stream.ID)
			c.mu.Unlock()
			close(stream.CloseCh)
		}
	}()

	c.nextStreamID++

	fmt.Println("=> Preparing to lock")
	c.mu.Lock()
	fmt.Println("=> Locked")
	c.streams[stream.ID] = stream
	fmt.Println("=> Wrote ")
	c.mu.Unlock()
	fmt.Println("=> Unlocked")

	switch kind {
	case "dir":
		fmt.Println("=> Sending begin dir")
		if err := stream.beginDir(); err != nil {
			return nil, err
		}
		fmt.Println("=> Sent begin dir Done")
	}
	stream.State = STREAM_OPEN
	fmt.Println("=> Starting main loop")
	go stream.loop()
	suc = true
	return stream, nil
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.Reader.Read(b)
}

// Write writes everything in RELAY_DATA cells
func (s *Stream) Write(b []byte) (int, error) {
	if s.State != STREAM_OPEN {
		return 0, errors.New("stream is not open")
	}

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
			s.SendWindow--
			s.circuit.SendWindow--
		case <-s.CloseCh:
			return wrote, errors.New("connection closed")
		}
	}
	return wrote, nil
}

func (s *Stream) loop() {
	for {

		if s.ReceiveWindow%50 == 0 && s.ReceiveWindow != 500 {
			select {
			case s.circuit.WriteRelayCell <- &relay.SendMeCell{
				StreamID:        s.ID,
				Version:         1,
				Sha1ForLastCell: [20]byte(s.circuit.BackWardsDigest.Sum(nil)),
			}:
				s.ReceiveWindow += 50
			case <-s.CloseCh:
				s.Close()
				return
			}
		}

		select {
		case cell := <-s.Inbound:
			s.handleCell(cell)
		case <-s.CloseCh:
			s.Close()
			return
		}
	}
}

func (s *Stream) Close() {

	end := relay.RelayEndCell{
		StreamID: s.ID,
	}
	s.circuit.WriteRelayCell <- &end

	s.State = STREAM_CLOSED

	close(s.CloseCh)
	s.Writer.Close()
	s.Reader.Close()

}

func (s *Stream) handleCell(cell relay.Cell) {
	switch cell.ID() {
	case relay.COMMAND_DATA:
		// Shrinking the ReceiveWindow
		s.ReceiveWindow--
		s.circuit.ReceiveWindow--

		// Writing data to the stream pipe
		dataCell := cell.(*relay.DataCell)
		_, err := s.Writer.Write(dataCell.Payload)
		if err != nil {
			s.Close()
		}
	case relay.COMMAND_RELAY_END:
		s.State = STREAM_CLOSED

		close(s.CloseCh)
		s.Writer.Close()
	}
}
