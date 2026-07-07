package shared

import "net"

type Addr struct {
	Kind, Addr string
}

func NewAddr(network, addr string) net.Addr {
	return &Addr{Kind: network, Addr: addr}
}

func (a *Addr) Network() string { return a.Kind }
func (a *Addr) String() string  { return a.Addr }
