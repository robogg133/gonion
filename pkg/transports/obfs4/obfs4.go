package obfs4

import (
	"net"

	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"golang.org/x/net/proxy"
)

func Dial(addr, nodeID, cert, iatMode string) (net.Conn, error) {
	transport := new(obfs4.Transport)

	fac, err := transport.ClientFactory("")
	if err != nil {
		return nil, err
	}

	args := &pt.Args{}

	args.Add("cert", cert)
	args.Add("iat-mode", iatMode)
	args.Add("node-id", nodeID)

	obfsArgs, err := fac.ParseArgs(args)
	if err != nil {
		return nil, err
	}

	return fac.Dial("tcp", addr, proxy.Direct.Dial, obfsArgs)
}
