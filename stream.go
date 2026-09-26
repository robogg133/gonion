package gonion

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/robogg133/gonion/internal/shared"
	"github.com/robogg133/gonion/internal/window"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/smallnest/ringbuffer"
)

const (
	STREAM_OPENING uint8 = iota
	STREAM_OPEN
	STREAM_CLOSED
)

const (
	STREAM_BUFFER_SIZE            = 256 << 10
	STREAM_SENDME_AMMOUNT_TRIGGER = 10 * relay.RELAY_BODY_LEN
)

type Stream struct {
	ID               uint16
	myHopDestination int
	circuit          *Circuit
	addr             net.Addr
	localAddr        net.Addr

	InboundControl chan relay.Cell
	Ctx            context.Context
	ctxCancel      context.CancelCauseFunc
	outbound       chan RelayOut
	Reader         io.ReadCloser
	buffer         *ringbuffer.RingBuffer
	readReady      chan struct{}
	SendWindow     *window.Window
	ReceiveWindow  *window.Window

	// State is retained for source compatibility. Concurrent callers must use
	// the connection methods rather than reading or writing this field.
	State         uint8
	mu            sync.RWMutex
	writeMu       sync.Mutex
	closeOnce     sync.Once
	stopParent    func() bool
	readDeadline  streamDeadline
	writeDeadline streamDeadline
	receiveSendMe chan struct{}
}

// newStream installs a stream before BEGIN/CONNECTED, so optimistic DATA can
// already be buffered. The caller reserves its ID under Circuit.streamMu.
func (c *Circuit) newStream(id uint16, target string, hopDest int) *Stream {
	log := logger(c.Ctx).With().Str("component", "stream").Uint16("stream_id", id).Int("hop", hopDest).Logger()
	ctx, cancel := context.WithCancelCause(withLogger(c.Ctx, log))
	s := &Stream{
		ID: id, circuit: c, myHopDestination: hopDest, addr: shared.NewAddr("tcp", target),
		InboundControl: make(chan relay.Cell, 16), outbound: make(chan RelayOut, 32),
		Ctx: ctx, ctxCancel: cancel, receiveSendMe: make(chan struct{}, 1),
		SendWindow: window.NewWindow(500, 50), ReceiveWindow: window.NewWindow(500, 50),
		State: STREAM_OPENING, buffer: ringbuffer.New(STREAM_BUFFER_SIZE), readReady: make(chan struct{}, 1),
	}
	s.Reader = &readCloserWrapper{buff: s.buffer, stream: s}
	c.streams.Set(id, s)
	s.mu.Lock()
	s.stopParent = context.AfterFunc(c.Ctx, func() { _ = s.Close() })
	s.mu.Unlock()
	return s
}

func (c *Circuit) NewStream(target string, hopDest int) (*Stream, error) {
	if c.Ctx.Err() != nil {
		return nil, context.Cause(c.Ctx)
	}
	if hopDest < 0 || hopDest >= c.hops.Len() {
		return nil, ErrInvalidHop
	}
	c.streamMu.Lock()
	// IDs may not be reused, even after a stream is closed (tor-spec 6.2).
	for c.nextStreamID <= 65535 && (c.nextStreamID == 0 || c.usedStreamIDs[c.nextStreamID/8]&(1<<(c.nextStreamID%8)) != 0) {
		c.nextStreamID++
	}
	if c.nextStreamID > 65535 {
		c.streamMu.Unlock()
		return nil, Public(ErrStream, "circuit stream IDs exhausted")
	}
	id := uint16(c.nextStreamID)
	c.nextStreamID++
	c.usedStreamIDs[id/8] |= 1 << (id % 8)
	s := c.newStream(id, target, hopDest)
	c.streamMu.Unlock()
	var err error
	if target == "dir" {
		err = s.beginDir()
	} else {
		err = s.begin(target)
	}
	if err != nil {
		_ = s.Free()
		return nil, err
	}
	if !s.open() {
		_ = s.Free()
		return nil, net.ErrClosed
	}
	return s, nil
}

func (s *Stream) open() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State != STREAM_OPENING || s.Ctx.Err() != nil {
		return false
	}
	s.State = STREAM_OPEN
	go s.controlLoop()
	go s.sendController()
	return true
}

func (s *Stream) controlLoop() {
	for {
		select {
		case cell := <-s.InboundControl:
			switch cell.ID() {
			case relay.COMMAND_SENDME:
				// Stream SENDMEs have no digest/version. Require an outstanding
				// group of 50 DATA cells before granting more credit.
				select {
				case <-s.SendWindow.Get():
					s.SendWindow.Increase()
					select {
					case s.receiveSendMe <- struct{}{}:
					default:
					}
				default:
					s.circuit.ctxCancel(Public(ErrSendMe, "unsolicited stream SENDME"))
					return
				}
			case relay.COMMAND_RELAY_END:
				_ = s.Close()
				return
			default:
				s.circuit.ctxCancel(Public(ErrProtocolViolation, "unexpected stream control cell"))
				return
			}
		case <-s.Ctx.Done():
			return
		}
	}
}

func (s *Stream) sendController() {
	for {
		select {
		case out := <-s.outbound:
			if out.Cell.ID() == relay.COMMAND_DATA {
				for s.SendWindow.IsZero() {
					select {
					case <-s.receiveSendMe:
					case <-s.Ctx.Done():
						return
					}
				}
				s.SendWindow.Subtract(1)
			}
			select {
			case s.circuit.WriteRelayCell <- out:
			case <-s.Ctx.Done():
				return
			}
		case <-s.Ctx.Done():
			return
		}
	}
}

func (s *Stream) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	open := s.State == STREAM_OPEN
	s.mu.RUnlock()
	if !open {
		return 0, net.ErrClosed
	}
	wrote := 0
	sent := make(chan error, 1)
	for len(b) != 0 {
		n := min(len(b), relay.RELAY_BODY_LEN)
		cell := &relay.DataCell{StreamID: s.ID, Payload: bytes.Clone(b[:n])}
		if err := s.sendCell(cell, sent); err != nil {
			return wrote, err
		}
		// A completed Write must not leave DATA behind a later END or circuit
		// shutdown. Acknowledge the actual link write, not just queue insertion.
		select {
		case err := <-sent:
			if err != nil {
				return wrote, err
			}
		case <-s.writeDeadline.wait():
			return wrote, os.ErrDeadlineExceeded
		case <-s.Ctx.Done():
			return wrote, net.ErrClosed
		}
		b, wrote = b[n:], wrote+n
	}
	return wrote, nil
}

func (s *Stream) SendCell(cell relay.Cell) error { return s.sendCell(cell, nil) }

func (s *Stream) sendCell(cell relay.Cell, sent chan error) error {
	if cell == nil {
		return Public(ErrProtocolViolation, "nil stream cell")
	}
	if s.Ctx.Err() != nil {
		return net.ErrClosed
	}
	cell.SetStreamID(s.ID)
	deadline := s.writeDeadline.wait()
	select {
	case <-deadline:
		return os.ErrDeadlineExceeded
	default:
	}
	select {
	case s.outbound <- RelayOut{Cell: cell, Dst: s.myHopDestination, sent: sent}:
		return nil
	case <-deadline:
		return os.ErrDeadlineExceeded
	case <-s.Ctx.Done():
		return net.ErrClosed
	}
}

// queueControl cannot block a circuit's receive loop behind DATA flow control.
// On local queue exhaustion we fail the circuit, never silently lose control.
func (s *Stream) queueControl(cell relay.Cell) {
	cell.SetStreamID(s.ID)
	select {
	case s.circuit.writeControl <- RelayOut{Cell: cell, Dst: s.myHopDestination}:
	case <-s.circuit.Ctx.Done():
	default:
		s.circuit.ctxCancel(Public(ErrCircuit, "stream control queue exhausted"))
	}
}

func (s *Stream) End(reason uint8) error {
	if s.Ctx.Err() == nil {
		s.queueControl(&relay.RelayEndCell{Reason: reason})
	}
	return s.Free()
}

func (s *Stream) Free() error {
	_ = s.Close()
	return s.Reader.Close()
}

// Close handles remote END too: queued input remains readable through EOF.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.State = STREAM_CLOSED
		stop := s.stopParent
		s.mu.Unlock()
		if stop != nil {
			stop()
		}
		s.ctxCancel(ErrStreamClosed)
		s.buffer.CloseWriter()
		select {
		case s.readReady <- struct{}{}:
		default:
		}
		s.circuit.streams.Delete(s.ID)
		s.circuit.closeServiceIfIdle()
	})
	return nil
}

func (s *Stream) writeDataCell(cell *relay.DataCell) error {
	if s.ReceiveWindow.Value() <= 0 {
		return Public(ErrProtocolViolation, "stream receive window exceeded")
	}
	s.ReceiveWindow.Subtract(1)
	if _, err := s.buffer.Write(cell.Payload); err != nil {
		return err
	}
	select {
	case s.readReady <- struct{}{}:
	default:
	}
	return nil
}

func (s *Stream) Conn() net.Conn { return &netWrapper{s: s} }

type netWrapper struct{ s *Stream }

func (w *netWrapper) Write(p []byte) (int, error)        { return w.s.Write(p) }
func (w *netWrapper) Read(p []byte) (int, error)         { return w.s.Reader.Read(p) }
func (w *netWrapper) SetWriteDeadline(t time.Time) error { w.s.writeDeadline.set(t); return nil }
func (w *netWrapper) SetReadDeadline(t time.Time) error  { w.s.readDeadline.set(t); return nil }
func (w *netWrapper) SetDeadline(t time.Time) error {
	w.s.readDeadline.set(t)
	w.s.writeDeadline.set(t)
	return nil
}
func (w *netWrapper) LocalAddr() net.Addr {
	if w.s.localAddr != nil {
		return w.s.localAddr
	}
	return shared.NewAddr("tor", "client")
}
func (w *netWrapper) RemoteAddr() net.Addr { return w.s.addr }
func (w *netWrapper) Close() error         { return w.s.End(relay.END_REASON_DONE) }

// Like net.Pipe, a deadline is a replaceable closed channel. Changing it wakes
// operations already blocked on that deadline; zero removes the deadline.
type streamDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func (d *streamDeadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel == nil {
		d.cancel = make(chan struct{})
	}
	return d.cancel
}

func (d *streamDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil
	closed := false
	if d.cancel == nil {
		d.cancel = make(chan struct{})
	}
	select {
	case <-d.cancel:
		closed = true
	default:
	}
	if t.IsZero() || time.Until(t) > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		if !t.IsZero() {
			ch := d.cancel
			d.timer = time.AfterFunc(time.Until(t), func() { close(ch) })
		}
	} else if !closed {
		close(d.cancel)
	}
}
