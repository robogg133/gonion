package gonion

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

func testStream(t *testing.T, open bool) (*Circuit, *Stream) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &Circuit{Ctx: ctx, ctxCancel: cancel, streams: &streams{streams: make(map[uint16]*Stream)}, WriteRelayCell: make(chan RelayOut, 512), writeControl: make(chan RelayOut, 32)}
	s := c.newStream(1, ":80", 0)
	if open {
		s.open()
	} else {
		s.State = STREAM_OPEN
	}
	t.Cleanup(func() { cancel(net.ErrClosed); _ = s.Free() })
	return c, s
}

func TestStreamWriteCopiesAndCloseUnblocks(t *testing.T) {
	_, s := testStream(t, false)
	data := []byte("owned by caller")
	written := make(chan error, 1)
	go func() { _, err := s.Write(data); written <- err }()
	out := <-s.outbound
	select {
	case <-written:
		t.Fatal("Write returned before link acknowledgement")
	default:
	}
	out.sent <- nil
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if got := out.Cell.(*relay.DataCell).Payload; string(got) != "owned by caller" {
		t.Fatalf("borrowed write buffer: %q", got)
	}
	for i := 0; i < cap(s.outbound); i++ {
		s.outbound <- RelayOut{Cell: &relay.DataCell{}}
	}
	result := make(chan error, 1)
	go func() { _, err := s.Write([]byte{1}); result <- err }()
	if err := s.Conn().Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Write")
	}
}

func TestStreamDeadlines(t *testing.T) {
	_, s := testStream(t, false)
	conn := s.Conn()
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not affect pending Read")
	}
	conn.SetReadDeadline(time.Time{})
	if err := s.writeDataCell(&relay.DataCell{Payload: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("reset deadline: %d %v", n, err)
	}
	conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, err := conn.Write([]byte("b")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write timeout: %d %v", n, err)
	}
	conn.SetWriteDeadline(time.Time{})
	go func() { (<-s.outbound).sent <- nil }()
	if n, err := conn.Write([]byte("c")); n != 1 || err != nil {
		t.Fatalf("reset write deadline: %d %v", n, err)
	}
}

func TestStreamFlowControlAcrossWindows(t *testing.T) {
	// tor-spec 7.4: start at 500 cells, acknowledge each group of 50.
	c, s := testStream(t, true)
	result := make(chan error, 1)
	go func() { _, err := s.Write(bytes.Repeat([]byte{7}, 1500*relay.RELAY_BODY_LEN)); result <- err }()
	for i := 1; i <= 1500; i++ {
		select {
		case out := <-c.WriteRelayCell:
			if out.Cell.ID() != relay.COMMAND_DATA {
				t.Fatalf("unexpected %T", out.Cell)
			}
			out.sent <- nil
			if i%50 == 0 {
				s.InboundControl <- &relay.SendMeCell{StreamID: s.ID}
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("stalled at DATA %d: %v", i, context.Cause(c.Ctx))
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestStreamReadReturnsAllCreditsAndDrainsOnEnd(t *testing.T) {
	c, s := testStream(t, false)
	for i := 0; i < 150; i++ {
		if err := s.writeDataCell(&relay.DataCell{Payload: []byte{42}}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Reader.Read(make([]byte, 150)); n != 150 || err != nil {
		t.Fatalf("read: %d %v", n, err)
	}
	if s.ReceiveWindow.Value() != 500 || len(c.writeControl) != 3 {
		t.Fatal("lost stream SENDME credit")
	}
	if err := s.writeDataCell(&relay.DataCell{Payload: []byte("final")}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	got, err := io.ReadAll(s.Reader)
	if err != nil || string(got) != "final" {
		t.Fatalf("drain on END: %q %v", got, err)
	}
}

func TestStreamRejectsUnsolicitedCredit(t *testing.T) {
	c, s := testStream(t, true)
	s.InboundControl <- &relay.SendMeCell{StreamID: 1}
	select {
	case <-c.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("accepted unsolicited SENDME")
	}
}
