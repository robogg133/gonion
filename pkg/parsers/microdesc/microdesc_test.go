package microdesc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/robogg133/gonion/pkg/common"
)

func TestRoundTrip(t *testing.T) {
	m := &common.Microdesc{
		OnionKey:     []byte("fake rsa bytes"),
		NTorOnionKey: bytes.Repeat([]byte{1}, 32),
		IdEd25519:    bytes.Repeat([]byte{2}, 32),
		Family:       []common.Family{{Digest: []byte{0x01, 0x02}}, {Nickname: "nick1"}},
		Familys:      []*common.FamilyIDs{{Kind: "AAP", Value: []byte{0xbe, 0xef}}},
		ExitRules:    &common.Ports{},
	}
	m.ExitRules.SetPort(22, true)
	m.ExitRules.SetPort(443, true)

	b, err := (Parser{}).Format([]*common.Microdesc{m})
	if err != nil {
		t.Fatal(err)
	}

	idx := bytes.Index(b, []byte("\n\n"))
	if idx < 0 {
		t.Fatalf("no blank line block separator in:\n%s", b)
	}
	dig := sha256.Sum256(b[:idx+1])

	got, err := (Parser{}).Parse(bytes.NewReader(b), []string{base64.RawStdEncoding.EncodeToString(dig[:])})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] == nil {
		t.Fatalf("expected 1 matched microdesc, got %d", len(got))
	}
	if !reflect.DeepEqual(got[0], m) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v\n--- text ---\n%s", got[0], m, b)
	}
}