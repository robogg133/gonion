package window_test

import (
	"sync"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/window"
)

func TestNew_NotZero(t *testing.T) {
	w := window.NewWindow(1000, 100)
	if w.IsZero() {
		t.Fatal("new window should not be zero")
	}
}

func TestSubtract_ToZero(t *testing.T) {
	w := window.NewWindow(3, 1)
	w.SetDigest([20]byte{9})
	w.Subtract(1)
	w.Subtract(1)
	w.Subtract(1)
	if !w.IsZero() {
		t.Fatal("expected zero")
	}
}

func TestIncrease_FromZero(t *testing.T) {
	w := window.NewWindow(0, 50)
	if !w.IsZero() {
		t.Fatal("start at 0")
	}
	w.Increase()
	if w.IsZero() {
		t.Fatal("after Increase should be non-zero")
	}
}

func TestTrigger_EveryAddValue(t *testing.T) {
	w := window.NewWindow(100, 25)
	dig := [20]byte{1, 2, 3, 4, 5}
	w.SetDigest(dig)

	for range 4 {
		w.Subtract(25)
	}

	got := 0
drain:
	for {
		select {
		case d := <-w.Get():
			if d != dig {
				t.Fatalf("digest = %x, want %x", d, dig)
			}
			got++
		default:
			break drain
		}
	}
	if got != 4 {
		t.Fatalf("triggers = %d, want 4", got)
	}
}

func TestTrigger_UsesLatestDigest(t *testing.T) {
	w := window.NewWindow(50, 50)
	w.SetDigest([20]byte{1})
	w.SetDigest([20]byte{2})
	w.Subtract(50)

	select {
	case d := <-w.Get():
		if d != [20]byte{2} {
			t.Fatalf("got %x", d)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestSubtract_WithoutDigest_NoPanic(t *testing.T) {
	w := window.NewWindow(10, 10)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	w.Subtract(10)
	select {
	case d := <-w.Get():
		if d != [20]byte{} {
			t.Fatalf("want zero digest, got %x", d)
		}
	default:
		t.Fatal("expected trigger")
	}
}

func TestConcurrent_Subtract(t *testing.T) {
	w := window.NewWindow(1000, 100)
	w.SetDigest([20]byte{7})

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Subtract(1)
		}()
	}
	wg.Wait()

	// 1000-100=900; boundaries at 900,800,...,100 may all fire (up to buffer).
	if w.IsZero() {
		t.Fatal("window should remain non-zero (900)")
	}
	select {
	case <-w.Get():
	default:
		t.Fatal("expected at least one SENDME trigger at a 100-cell boundary")
	}
}

func TestGetDigest_DefaultAndSet(t *testing.T) {
	w := window.NewWindow(1, 1)
	if w.GetDigest() != [20]byte{} {
		t.Fatal("unset digest should be zero value")
	}
	w.SetDigest([20]byte{0xff})
	if w.GetDigest()[0] != 0xff {
		t.Fatal("GetDigest mismatch")
	}
}

func TestAddAndSet(t *testing.T) {
	w := window.NewWindow(0, 1)
	w.Set(5)
	if w.IsZero() {
		t.Fatal("Set(5)")
	}
	w.Add(-5)
	if !w.IsZero() {
		t.Fatal("Add(-5) should zero")
	}
}

func TestTrigger_ChannelDoesNotBlock(t *testing.T) {
	// Buffer is start/add = 1; flooding triggers must not block Subtract.
	w := window.NewWindow(10, 10)
	w.SetDigest([20]byte{1})
	done := make(chan struct{})
	go func() {
		for range 20 {
			w.Set(10)
			w.Subtract(10)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Subtract blocked on full trigger channel")
	}
}
