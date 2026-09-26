package embed

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/robogg133/gonion/pkg/hs"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

// ServiceOptions contains caller-owned identity and revision persistence policy.
type ServiceOptions = hs.ServiceOptions

// Listener accepts onion streams without a local listening socket. Close stops
// publication and new accepts, but preserves accepted connections until they or
// the owning Client close. Err reports background publication failures.
type Listener struct {
	*hs.Listener
	client *Client
	once   sync.Once
}

// Listen waits for introduction establishment and descriptor publication, not
// a reachability probe. ctx controls initialization only. The caller must keep
// Identity private and persist NextRevision reservations before returning them.
func (c *Client) Listen(ctx context.Context, opts ServiceOptions) (*Listener, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	ctx, finish, err := c.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	builder, ok := c.builder.(capi.ContextCircuitBuilder)
	if !ok {
		return nil, fmt.Errorf("embed: Listen requires a context-aware circuit builder")
	}
	inner, err := hs.Listen(ctx, contextBuilder{ctx: ctx, lifetime: c.lifetime, builder: builder}, c.Consensus, opts)
	if err != nil {
		return nil, err
	}
	l := &Listener{Listener: inner, client: c}
	c.mu.Lock()
	if c.closed || ctx.Err() != nil {
		c.mu.Unlock()
		_ = inner.Shutdown()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, net.ErrClosed
	}
	if c.listeners == nil {
		c.listeners = make(map[*Listener]struct{})
	}
	c.listeners[l] = struct{}{}
	c.mu.Unlock()
	return l, nil
}

func (l *Listener) Close() error {
	l.once.Do(func() {
		_ = l.Listener.Close()
		l.client.mu.Lock()
		delete(l.client.listeners, l)
		l.client.mu.Unlock()
	})
	return nil
}

// Shutdown also closes already accepted streams. Client.Close calls it for
// active listeners and cancels circuits belonging to previously closed ones.
func (l *Listener) Shutdown() error {
	_ = l.Close()
	return l.Listener.Shutdown()
}

// operationContext binds pending work to Client.Close, without binding the
// lifetime of a returned connection/listener to the caller's initialization ctx.
func (c *Client) operationContext(parent context.Context) (context.Context, func(), error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, net.ErrClosed
	}
	if c.lifetime == nil {
		c.lifetime, c.cancel = context.WithCancel(context.Background())
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(c.lifetime, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

var _ net.Listener = (*Listener)(nil)
