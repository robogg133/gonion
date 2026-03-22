package gonion2

import "sync"

type circuits struct {
	circs map[uint32]*Circuit
	mu    sync.RWMutex
}

func (m *circuits) Set(id uint32, value *Circuit) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.circs[id] = value
}

func (m *circuits) Get(id uint32) *Circuit {
	m.mu.RLock()
	defer m.mu.RUnlock()
	defer recover()

	circ := m.circs[id]

	return circ
}

func (m *circuits) Delete(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.circs, id)
}

/////////////////////////////////////////////////

type streams struct {
	streams map[uint16]*Stream

	mu sync.RWMutex
}

func (m *streams) Set(id uint16, value *Stream) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.streams[id] = value
}

func (m *streams) Get(id uint16) *Stream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	defer recover()

	circ := m.streams[id]

	return circ
}

func (m *streams) Delete(id uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.streams, id)
}

/////////////////////////////////////////////////

type window struct {
	v uint16

	mu sync.RWMutex
}

func (w *window) Set(n uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.v = n
}

func (w *window) Add(n uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.v += n
}

func (w *window) Subtract(n uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.v -= n
}

func (w *window) Get() uint16 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.v
}

/////////////////////////////////////////////////
