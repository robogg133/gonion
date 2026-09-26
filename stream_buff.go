package gonion

import (
	"net"
	"os"
	"sync"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/smallnest/ringbuffer"
)

type readCloserWrapper struct {
	buff   *ringbuffer.RingBuffer
	stream *Stream
	mu     sync.Mutex
}

func (r *readCloserWrapper) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		deadline := r.stream.readDeadline.wait()
		select {
		case <-deadline:
			return 0, os.ErrDeadlineExceeded
		default:
		}
		n, err := r.buff.Read(p)
		if n > 0 {
			// Drain every outstanding credit when the application has consumed
			// the queue. A single read can cross several SENDME boundaries.
			for r.buff.Length() < STREAM_SENDME_AMMOUNT_TRIGGER {
				select {
				case <-r.stream.ReceiveWindow.Get():
					r.stream.ReceiveWindow.Increase()
					r.stream.queueControl(&relay.SendMeCell{StreamID: r.stream.ID})
				default:
					return n, nil
				}
			}
			return n, nil
		}
		if err != ringbuffer.ErrIsEmpty {
			return n, err
		}
		select {
		case <-r.stream.readReady:
		case <-deadline:
			return 0, os.ErrDeadlineExceeded
		case <-r.stream.Ctx.Done():
			_ = r.stream.Close()
		}
	}
}

func (r *readCloserWrapper) Close() error {
	r.buff.CloseWithError(net.ErrClosed)
	select {
	case r.stream.readReady <- struct{}{}:
	default:
	}
	return nil
}
