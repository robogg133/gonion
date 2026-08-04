package hs

import "net"

// Listener accepts connections to a hidden service. It is a thin wrapper around
// a plain net.Listener; onion-circuit wiring happens at the caller. ponytail:
// the rendezvous/introduction plumbing is out of scope here — this just gives
// the hs package a net.Listener to grow into.
type Listener struct {
	net.Listener
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: c}, nil
}

// Conn is a single accepted hidden-service connection.
type Conn struct {
	net.Conn
}
