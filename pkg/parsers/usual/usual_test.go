package usual

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"fmt"
	"strings"
	"testing"

	"github.com/robogg133/gonion/pkg/common"
)

//go:embed testdata/*.fixture
var capturedFixtures embed.FS

// Read only package-owned, hash-pinned excerpts, never live-test output.
// Provenance and the deliberately invalidated signatures are documented in
// testdata/README.md. These fixtures test parsing, not authentication.
func capturedFixture(t *testing.T, flavor string) []byte {
	t.Helper()
	want := map[string]string{
		common.ConsensusFlavorNS:        "311f5cce0d5ce24fe80c3078eeb6d298efd5c408da407182b3a20b3d8c655d04",
		common.ConsensusFlavorMicrodesc: "4dfe402182196b7cb45bdff63df7560b1393ec1223c70d1ea06d869649d49fa9",
	}[flavor]
	data, err := capturedFixtures.ReadFile("testdata/" + flavor + ".fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("%s fixture SHA-256 = %s, want %s; review provenance before updating", flavor, got, want)
	}
	return data
}

// Captured excerpts are checked against dir-spec 3.4.1 and 3.9.2 layouts.
func TestCapturedFlavors(t *testing.T) {
	for _, tc := range []struct{ flavor, digest, secondDigest string }{
		{common.ConsensusFlavorNS, "BO/3BB69q10vySM69aT/SGdv50k", "5M+xXSiV0h7qQH+boXSuzcE8h8w"},
		{common.ConsensusFlavorMicrodesc, "fXPextdkQnmBDwYmo0UHLbUhaU6C0slh/NQVtZn1VU0", "xqtBGgHfpPjJFk3yMWGOZGfNYYpw4SlqIn0pOE0IngQ"},
	} {
		t.Run(tc.flavor, func(t *testing.T) {
			data := capturedFixture(t, tc.flavor)
			c, err := (Parser{}).Parse(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if c.Flavor != tc.flavor || len(c.RelayInformation) != 2 {
				t.Fatal("wrong flavor or relay count")
			}
			r := c.RelayInformation[0]
			if r.Nickname != "Quintex152" || r.Ipv4Addr != "204.8.96.141" || r.ORPort != 444 {
				t.Fatal("wrong router layout")
			}
			for i, want := range []string{tc.digest, tc.secondDigest} {
				router := c.RelayInformation[i]
				got, other := router.DescriptorDigest, router.MicrodescriptorDigest
				if tc.flavor == common.ConsensusFlavorMicrodesc {
					got, other = other, got
				}
				if got != want || other != "" {
					t.Fatalf("router %d: digest = %q, want %q; other-flavor digest = %q", i, got, want, other)
				}
			}
			if c.IsAuthenticated() {
				t.Fatal("structural parsing authenticated an excerpt")
			}
			out, err := (Parser{}).Format(c)
			if err != nil || !bytes.Equal(out, data) {
				t.Fatal("original bytes not preserved", err)
			}
		})
	}
}

func TestConsensusWeightDefaultsAndZero(t *testing.T) {
	data := capturedFixture(t, common.ConsensusFlavorMicrodesc)
	// Keep the captured document layout; these structural parser tests do not
	// authenticate the modified signature. path-spec 2.2 and dir-spec 3.4.1.
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "params ") && !strings.HasPrefix(line, "bandwidth-weights ") {
			lines = append(lines, line)
		}
	}
	base := strings.Join(lines, "\n")
	for _, tc := range []struct {
		name, params, weights string
		guard, middle         int32
		bad                   bool
	}{
		{"absent", "", "", 10000, 10000, false},
		{"zero", "", "Wgg=0 Wme=1", 0, 1, false},
		{"negative", "", "Wgg=-1 Wme=0", 10000, 0, false},
		{"malformed", "", "Wgg=invalid Wme=2147483648", 10000, 10000, false},
		{"scaled", "bwweightscale=5000", "Wgg=5001 Wme=0", 5000, 0, false},
		{"scaled-absent", "bwweightscale=5000", "", 5000, 5000, false},
		{"duplicate", "", "Wgg=0 Wgg=1", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(base, "vote-status consensus\n", "vote-status consensus\nparams "+tc.params+"\n", 1)
			if tc.weights != "" {
				input = strings.Replace(input, "directory-footer\n", "directory-footer\nbandwidth-weights "+tc.weights+"\n", 1)
			}
			c, err := (Parser{}).Parse(strings.NewReader(input))
			if tc.bad {
				if err == nil {
					t.Fatal("duplicate weights accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.BandWidthWeight.Wgg != tc.guard || c.BandWidthWeight.Wme != tc.middle || c.IsAuthenticated() {
				t.Fatalf("wrong weight defaults: %+v", c.BandWidthWeight)
			}
		})
	}
}

func TestMalformedConsensus(t *testing.T) {
	data := capturedFixture(t, common.ConsensusFlavorMicrodesc)
	s := string(data)
	for name, input := range map[string]string{
		"empty": "", "truncated": s[:strings.Index(s, "directory-footer")],
		"vote":         strings.Replace(s, "vote-status consensus", "vote-status vote", 1),
		"flavor":       strings.Replace(s, "3 microdesc", "3 unknown", 1),
		"wrong-layout": strings.Replace(s, "3 microdesc", "3", 1),
		"short-id":     strings.Replace(s, "AAjZZA/klH9z41X2fiDC0pC7xyw", "AA", 1),
		"bad-port":     strings.Replace(s, "204.8.96.141 444 0", "204.8.96.141 65536 0", 1),
		"bad-pr":       strings.Replace(s, "Link=3-5", "Link=3-", 1),
		"bad-time":     strings.Replace(s, "valid-after 2026-08-22 17:00:00", "valid-after invalid", 1),
		"duplicate":    "network-status-version 3 microdesc\n" + s,
		"long-line":    strings.Replace(s, "vote-status consensus", "x-unknown "+strings.Repeat("x", 65536), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if input == s {
				t.Fatal("malformed-input mutation did not change the fixture")
			}
			if _, err := (Parser{}).Parse(strings.NewReader(input)); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	input := strings.Replace(s, "\nm fXP", "\nx-future ignored\nm fXP", 1)
	if _, err := (Parser{}).Parse(strings.NewReader(input)); err != nil {
		t.Fatal("unknown router keyword ended section", err)
	}
	if _, err := (Parser{}).Format(&common.Consensus{}); err == nil {
		t.Fatal("fabricated unsigned consensus")
	}
}
