package window

import "sync/atomic"

type Window struct {
	v int32

	digest atomic.Value

	startValue int32
	addValue   int32
}

func NewWindow(startValue, addValue int32) *Window {
	return &Window{
		v:          startValue,
		startValue: startValue,
		addValue:   addValue,
	}
}

// Increase window.v += window.addValue
func (w *Window) Increase() {
	atomic.AddInt32(&w.v, w.addValue)
}

// Check if window need a SENDME
func (w *Window) Check() bool {
	wn := atomic.LoadInt32(&w.v)
	return wn != w.startValue && wn%w.addValue == 0
}

// Check if window need a SENDME if need return true and add window.startValue to value
func (w *Window) IncreaseWindowChecking() bool {

	if w.Check() {
		w.Increase()
		return true
	}

	return false
}

func (w *Window) Set(n int32) {
	atomic.StoreInt32(&w.v, n)
}

func (w *Window) Add(n int32) {
	atomic.AddInt32(&w.v, n)
}

func (w *Window) Subtract(n int32) {
	atomic.AddInt32(&w.v, -n)
}

func (w *Window) Get() int32 {
	return atomic.LoadInt32(&w.v)
}

func (w *Window) SetDigest(digest [20]byte) {
	w.digest.Store(digest)
}

func (w *Window) GetDigest() [20]byte {
	return w.digest.Load().([20]byte)
}
