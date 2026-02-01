package client

import (
	"io"
	"net"
	"time"

	"github.com/robogg133/gonion/connection"
	"github.com/robogg133/gonion/connection/cells"
)

type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type Wrapper struct {
	base connection.TORConnection
	pr   *io.PipeReader
	pw   *io.PipeWriter
}

func newWrapper(base connection.TORConnection) *Wrapper {
	pr, pw := io.Pipe()

	return &Wrapper{
		base: base,
		pr:   pr,
		pw:   pw,
	}
}

func (wrapper *Wrapper) Read(b []byte) (n int, err error) {

	return 0, nil
}

func (wrapper *Wrapper) Close() error {

	c := cells.DestroyCell{
		CircuitID: wrapper.base.CircuitID,
		Reason:    0,
	}

	if _, err := wrapper.base.Conn.Write(c.Serialize()); err != nil {
		return err
	}

	return wrapper.base.Conn.Close()
}
