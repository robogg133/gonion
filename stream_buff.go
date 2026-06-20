package gonion

import (
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/smallnest/ringbuffer"
)

type readCloserWrapper struct {
	buff   *ringbuffer.RingBuffer
	stream *Stream
}

func (r *readCloserWrapper) Read(p []byte) (int, error) {

	sent := false
	wantRead := len(p)

	if wantRead > r.buff.Length() {
		if r.stream.ReceiveWindow.IncreaseWindowChecking() {
			r.stream.SendCell(&relay.SendMeCell{
				StreamID:        r.stream.ID,
				Version:         r.stream.circuit.SendMeVersion,
				Sha1ForLastCell: r.stream.circuit.hops[r.stream.myHopDestination].Backwards.GetLastSumDataCell(),
			})

			sent = true
		}
	}

	n, err := r.buff.Read(p)

	if !sent && r.buff.Length() < STREAM_SENDME_AMMOUNT_TRIGGER {
		if r.stream.ReceiveWindow.IncreaseWindowChecking() {
			r.stream.SendCell(&relay.SendMeCell{
				StreamID:        r.stream.ID,
				Version:         r.stream.circuit.SendMeVersion,
				Sha1ForLastCell: r.stream.circuit.hops[r.stream.myHopDestination].Backwards.GetLastSumDataCell(),
			})
		}
	}

	return n, err
}

func (r *readCloserWrapper) Close() error { return r.buff.ReadCloser().Close() }
