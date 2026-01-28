package connection

import (
	"github.com/robogg133/gonion/shared"
)

var ANON_PORTS []uint16 = []uint16{443, 8443, 80}

func isAnonPort(port uint16) bool {
	for _, v := range ANON_PORTS {
		if v == port {
			return true
		}
	}
	return false
}

func SelectFirstFromFallBackAnonPorts() (*shared.FallbackDir, error) {

	for _, v := range shared.Fallbacks {
		if isAnonPort(v.ORPort) {
			return &v, nil
		}
	}

	return nil, nil
}
