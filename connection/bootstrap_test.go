package connection_test

import (
	"testing"

	"github.com/robogg133/gonion/connection"
)

func TestCreateConn(t *testing.T) {

	fallBack, err := connection.SelectFirstFromFallBackAnonPorts()
	if err != nil {
		t.Error(err)
	}

	if _, err := connection.CreateConnection(fallBack.IPv4, fallBack.ORPort); err != nil {
		t.Error(err)
	}
}
