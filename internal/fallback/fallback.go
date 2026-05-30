package fallback

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/robogg133/gonion/internal/shared"
)

type FallBackDialer struct {
	list []shared.FallbackDir
}

func New(list []shared.FallbackDir) *FallBackDialer {
	return &FallBackDialer{
		list: list,
	}
}

func (fb *FallBackDialer) Dial(tryipv6 bool) (net.Conn, error) {

	var allErrors string
	for _, v := range fb.list {
		stop := false

		addr := fmt.Sprintf("%s:%d", v.IPv4, v.ORPort)

	dial:
		conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
		if err == nil {
			return conn, nil
		}
		allErrors = allErrors + addr + " ->" + err.Error() + "\n"

		if !tryipv6 || stop || v.IPv6 == "" {
			continue
		}

		addr = fmt.Sprintf("[%s]:%d", v.IPv6, v.ORPort)
		stop = true
		goto dial
	}
	return nil, errors.New(allErrors)
}
