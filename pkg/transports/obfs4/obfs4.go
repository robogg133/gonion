package obfs4

import (
	"context"
	"net"

	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

func Dial(addr, nodeID, cert, iatMode string) (net.Conn, error) {
	return DialContext(context.Background(), addr, nodeID, cert, iatMode)
}

// DialContext cancels both TCP establishment and the obfs4 handshake. After a
// successful return, ctx no longer controls the returned connection's lifetime.
func DialContext(ctx context.Context, addr, nodeID, cert, iatMode string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

	var raw net.Conn
	var stop func() bool
	conn, err := fac.Dial("tcp", addr, func(network, address string) (net.Conn, error) {
		var dialErr error
		raw, dialErr = (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr == nil {
			stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
		}
		return raw, dialErr
	}, obfsArgs)
	if stop != nil {
		stop()
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, err
	}
	return conn, nil
}
