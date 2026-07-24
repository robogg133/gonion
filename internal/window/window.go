package window

import (
	"sync/atomic"
)

type Window struct {
	v int32

	digest atomic.Value

	startValue int32
	addValue   int32

	Trigged chan [20]byte
}

func NewWindow(startValue, addValue int32) *Window {
	return &Window{
		v:          startValue,
		startValue: startValue,
		addValue:   addValue,
		Trigged:    make(chan [20]byte, startValue/addValue),
	}
}

// Increase window.v += window.addValue
func (w *Window) Increase() {
	atomic.AddInt32(&w.v, w.addValue)
}

func (w *Window) Set(n int32) {
	atomic.StoreInt32(&w.v, n)
}

func (w *Window) Add(n int32) {
	atomic.AddInt32(&w.v, n)
}

func (w *Window) Subtract(n int32) {
	value := atomic.AddInt32(&w.v, -n)
	if value%w.addValue == 0 {
		var digest [20]byte
		if v := w.digest.Load(); v != nil {
			digest = v.([20]byte)
		}
		select {
		case w.Trigged <- digest:
		default:
		}
	}
}

func (w *Window) IsZero() bool {
	return atomic.LoadInt32(&w.v) <= 0
}

func (w *Window) Get() <-chan [20]byte {
	return w.Trigged
}

func (w *Window) SetDigest(digest [20]byte) {
	w.digest.Store(digest)
}

func (w *Window) GetDigest() [20]byte {
	if v := w.digest.Load(); v != nil {
		return v.([20]byte)
	}
	return [20]byte{}
}
