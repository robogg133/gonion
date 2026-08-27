package onion_test

import (
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/robogg133/gonion/pkg/hs/onion"
)

const testAddr = "tbup4alxvo3wmessgrbjfbfpny6x5xab56do6sli6i6b42sgreisrfqd.onion"

func TestOnionAddrFromString(t *testing.T) {
	o, err := onion.NewFromString(testAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pk=%x,pk_len=%d,version=%d", o.Pk, len(o.Pk), o.Version)
}

func TestOnionAddr(t *testing.T) {
	o := new(onion.OnionHostname)
	pk := make([]byte, 32)
	io.ReadFull(rand.Reader, pk)

	o.Pk = [32]byte(pk)
	o.Version = 3

	addr := strings.TrimSuffix(o.String(), ".onion")
	if len(addr) != 56 {
		t.Fatal("onion addr must be 56 char len")
	}
	t.Log(o.String())
}
