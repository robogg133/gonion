package gonion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers/microdesc"
)

func TestHydrationSnapshots(t *testing.T) {
	data, err := os.ReadFile("pkg/parsers/microdesc/tor-test-md.fixture")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	d := base64.RawStdEncoding.EncodeToString(digest[:])
	now := time.Now().UTC()
	c := &common.Consensus{NetowrkStatusVersion: 3, Flavor: ConsensusFlavorMicrodesc, ValidAfter: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), ValidUntil: now.Add(2 * time.Hour), RelayInformation: []common.RouterStatus{{Nickname: "test005r", NodeID: [20]byte{1}, Ipv4Addr: "127.0.0.1", ORPort: 5005, MicrodescriptorDigest: d}}}
	before := c.Clone()
	fetch := func(ds []string) ([]*common.Microdesc, error) {
		return (microdesc.Parser{}).Parse(bytes.NewReader(data), ds)
	}
	out, err := hydrateConsensus(context.Background(), c, nil, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !out.IsHydrated() || !reflect.DeepEqual(c, before) {
		t.Fatal("hydration mutated input or remained incomplete")
	}
	common.SetGlobalConsensus(out)
	defer common.SetGlobalConsensus(nil)
	old := common.GetGlobalConsensus()
	out.RelayInformation[0].IdEd25519[0] ^= 1
	if reflect.DeepEqual(out.RelayInformation[0].IdEd25519, common.GetGlobalConsensus().RelayInformation[0].IdEd25519) {
		t.Fatal("global aliases caller")
	}
	previous := old.Clone()
	candidate := c.Clone()
	candidate.RelayInformation[0].BandWidth = 999
	newer, err := hydrateConsensus(context.Background(), candidate, previous, func([]string) ([]*common.Microdesc, error) { t.Fatal("unchanged digest fetched"); return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if newer.RelayInformation[0].BandWidth != 999 {
		t.Fatal("reused stale consensus fields")
	}
	newer.RelayInformation[0].IdEd25519[0] ^= 1
	if !reflect.DeepEqual(previous, old) {
		t.Fatal("reuse aliases old snapshot")
	}
	for _, fetch := range []func([]string) ([]*common.Microdesc, error){func([]string) ([]*common.Microdesc, error) { return nil, errors.New("failed") }, func([]string) ([]*common.Microdesc, error) { return []*common.Microdesc{nil}, nil }} {
		if got, err := hydrateConsensus(context.Background(), c, nil, fetch); err == nil || got != nil {
			t.Fatal("partial candidate accepted")
		}
		if !reflect.DeepEqual(old, common.GetGlobalConsensus()) {
			t.Fatal("failure changed published snapshot")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hydrateConsensus(ctx, c, nil, fetch); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestDirectoryResponseBounds(t *testing.T) {
	for _, response := range []string{"HTTP/1.0 503 Busy\r\n\r\n", "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nshort", "HTTP/1.0 200 OK\r\nContent-Encoding: unknown\r\n\r\n"} {
		if _, err := readDirectoryResponse(bytes.NewBufferString(response), nil, 8); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	got, err := readDirectoryResponse(bytes.NewBufferString("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"), nil, 8)
	if err != nil || string(got) != "ok" {
		t.Fatal("valid response rejected", err)
	}
	if _, err := buildURL([]string{"../invalid"}); err == nil {
		t.Fatal("invalid digest accepted")
	}
	if _, _, err := consensusRequestPath("invalid"); err == nil {
		t.Fatal("invalid flavor accepted")
	}
}
