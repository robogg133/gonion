package gonion

import (
	"net"
	"time"
)

type Addr struct {
	currentAddr string
}

func (c *Conn) Read(b []byte) (n int, err error)  { return 0, nil }
func (c *Conn) Write(b []byte) (n int, err error) { return 0, nil }

func (c *Conn) Close() error {

	for _, circuit := range c.circuits {
		circuit.CloseCh <- struct{}{}
	}
	return c.socket.Close()
}

func (c *Conn) LocalAddr() net.Addr  { return nil }
func (c *Conn) RemoteAddr() net.Addr { return nil }

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	err := c.SetWriteDeadline(t)
	return err
}
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

func (*Addr) Network() string  { return "tor" }
func (a *Addr) String() string { return a.currentAddr }
