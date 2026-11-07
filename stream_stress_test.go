package gonion

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

func TestStreamConnClosePreservesDataEndFIFO(t *testing.T) {
	c, s := testStream(t, true)
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("data"))
		writeDone <- err
	}()

	data := <-c.WriteRelayCell
	if data.Cell.ID() != relay.COMMAND_DATA {
		t.Fatalf("first circuit cell = %d, want DATA", data.Cell.ID())
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Conn().Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close remained blocked without peer progress")
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Write")
	}

	end := <-c.WriteRelayCell
	if end.Cell.ID() != relay.COMMAND_RELAY_END {
		t.Fatalf("cell after DATA = %d, want END", end.Cell.ID())
	}
}

func TestStreamConcurrentWritesAndCloseAreBounded(t *testing.T) {
	_, s := testStream(t, false)
	const writers = 8
	for i := 0; i < cap(s.outbound); i++ {
		s.outbound <- RelayOut{Cell: &relay.DataCell{}}
	}

	var writersWG sync.WaitGroup
	writeResults := make(chan error, writers)
	writersWG.Add(writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer writersWG.Done()
			_, err := s.Write([]byte{byte(i)})
			writeResults <- err
		}(i)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Conn().Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Close remained blocked")
	}
	writersWG.Wait()
	close(writeResults)
	for err := range writeResults {
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("concurrent Write: %v", err)
		}
	}
}

func TestStreamCancellationAndDeadlinesReleaseBlockedOperations(t *testing.T) {
	_, s := testStream(t, false)
	conn := s.Conn()

	readDone := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); readDone <- err }()
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read survived deadline")
	}

	for i := 0; i < cap(s.outbound); i++ {
		s.outbound <- RelayOut{Cell: &relay.DataCell{}}
	}
	conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	writeDone := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("blocked")); writeDone <- err }()
	select {
	case err := <-writeDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Write survived deadline")
	}

	conn.SetWriteDeadline(time.Time{})
	cancelDone := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("cancelled")); cancelDone <- err }()
	s.ctxCancel(errors.New("test cancellation"))
	select {
	case err := <-cancelDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("cancelled Write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release Write")
	}
}
