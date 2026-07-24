package hops

import (
	"context"
	"errors"

	"github.com/robogg133/gonion/internal/window"
	"github.com/robogg133/gonion/pkg/cells/relay"
)

type Hop struct {
	rcv *window.Window
	snd *window.Window

	ctx    context.Context
	cancel context.CancelCauseFunc

	coder *relay.RelayCellCoder

	sendMe chan struct{}
}

var ErrCantDecrypt = errors.New("can not decrypt relay cell body")

func NewHop(ctx context.Context, coder *relay.RelayCellCoder, rcv, snd *window.Window) *Hop {
	ctx, cancel := context.WithCancelCause(ctx)
	return &Hop{
		ctx:    ctx,
		cancel: cancel,
		coder:  coder,
		rcv:    rcv,
		snd:    snd,
		sendMe: make(chan struct{}, 1),
	}
}

func (h *Hop) Recv() *window.Window { return h.rcv }
func (h *Hop) Send() *window.Window { return h.snd }
func (h *Hop) Ctx() context.Context { return h.ctx }

func (h *Hop) Cancel(err error) {
	if h.cancel != nil {
		h.cancel(err)
	}
}

func (h *Hop) NotifySendMe() {
	select {
	case h.sendMe <- struct{}{}:
	default:
	}
}

func (h *Hop) SendMe() <-chan struct{} {
	return h.sendMe
}

func (h *Hop) Marshal(rc relay.Cell) ([]byte, error) {
	return h.coder.Marshal(rc)
}

// ReadMessage modifies body in place. On success body is fully decrypted for this hop.
func (h *Hop) ReadMessage(body []byte) (relay.Cell, error) {
	h.coder.Backwards.XORKeyStream(body[0:], body)
	if relay.IsDecrypted(body) {
		return h.coder.UnmarshalPlain(body)
	}
	return nil, ErrCantDecrypt
}

func (h *Hop) XORKeyStream(dst, src []byte) {
	h.coder.Forwards.XORKeyStream(dst, src)
}
