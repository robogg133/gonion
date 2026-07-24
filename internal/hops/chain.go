package hops

import (
	"fmt"

	"github.com/robogg133/gonion/pkg/cells/relay"
)

type Chain struct {
	Hops []*Hop
}

func (c *Chain) Len() int {
	return len(c.Hops)
}

func (c *Chain) At(i int) *Hop {
	if i < 0 || i >= len(c.Hops) {
		return nil
	}
	return c.Hops[i]
}

func (c *Chain) Guard() *Hop {
	if len(c.Hops) == 0 {
		return nil
	}
	return c.Hops[0]
}

func (c *Chain) Exit() *Hop {
	if len(c.Hops) == 0 {
		return nil
	}
	return c.Hops[len(c.Hops)-1]
}

func (c *Chain) Append(h *Hop) {
	c.Hops = append(c.Hops, h)
}

// UnmarshalMessage peels onion layers from guard toward exit until a hop recognizes the cell.
// msg is modified in place.
func (c *Chain) UnmarshalMessage(msg []byte) (fromHop int, rc relay.Cell, err error) {
	if len(c.Hops) == 0 {
		return -1, nil, ErrCantDecrypt
	}
	for id, hop := range c.Hops {
		cell, err := hop.ReadMessage(msg)
		if err != nil {
			if err == ErrCantDecrypt {
				continue
			}
			return -1, nil, err
		}
		return id, cell, nil
	}
	return -1, nil, ErrCantDecrypt
}

// MarshalMessage encodes rc at hop dst and applies forward layers dst-1..0.
func (c *Chain) MarshalMessage(rc relay.Cell, dst int) ([]byte, error) {
	if dst < 0 || dst >= len(c.Hops) {
		return nil, fmt.Errorf("invalid destination: %d", dst)
	}
	b, err := c.Hops[dst].Marshal(rc)
	if err != nil {
		return nil, err
	}
	for i := dst - 1; i >= 0; i-- {
		c.Hops[i].XORKeyStream(b[0:], b)
	}
	return b, nil
}
