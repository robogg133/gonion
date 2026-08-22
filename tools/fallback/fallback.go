//go:generate sh -c "go run . && cd ../.. && mv ./tools/fallback/tor-gonion_fallback_dirs.go ./internal/shared && gofmt -w ./internal/shared/tor-gonion_fallback_dirs.go"
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/robogg133/gonion"
	"github.com/robogg133/gonion/internal/fallback"
	"github.com/robogg133/gonion/pkg/common"
)

const NumberOfRelays = 200
const HeaderComment = `/* type=fallback */
/* version=4.0.0 */
/* timestamp=20210412000000 */
/* source=offer-list */
`

func writeHeaderToFile(w io.Writer) {
	fmt.Fprint(w, HeaderComment)
	fmt.Fprintln(w, "//")
	fmt.Fprintf(w, "// Generated on: %s\n\n", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

func writeGoFormat(selected []common.RouterStatus, w io.Writer) {
	fmt.Fprintln(w, "package shared")
	fmt.Fprint(w, `type FallbackDir struct {
		IPv4        string
		ORPort      uint16
		Fingerprint string
		IPv6        string // empty string if don't
		IPv6Port    uint16 // 0 if don't
		Nickname    string
	}
`)
	fmt.Fprintln(w, "var Fallbacks = []FallbackDir{")
	for _, relay := range selected {
		fmt.Fprintln(w, "{")
		fmt.Fprintf(w, "IPv4:\"%s\",\n", relay.Ipv4Addr)
		fmt.Fprintf(w, "ORPort:%d,\n", relay.ORPort)
		fmt.Fprintf(w, "Fingerprint:\"%s\",\n", strings.ToUpper(hex.EncodeToString(relay.NodeID[:])))
		fmt.Fprintf(w, "Nickname:\"%s\",\n", relay.Nickname)

		if relay.Ipv6Addr != "" {
			fmt.Fprintf(w, "IPv6:\"%s\",\n", relay.Ipv6Addr)
			fmt.Fprintf(w, "IPv6Port:%d,\n", relay.ORPort)
		}

		fmt.Fprintln(w, "},")
	}
	fmt.Fprintln(w, "}")

}

func main() {
	c, err := fallback.Dial(false)
	if err != nil {
		panic(err)
	}
	conn, err := gonion.NewConn(c, io.Discard, false)
	if err != nil {
		panic(err)
	}
	fmt.Println("[+] Bootstraping to the Tor network...")
	circ, err := conn.NewFastCircuit(1)
	if err != nil {
		panic(err)
	}
	cns, err := circ.GetConsensus()
	if err != nil {
		panic(err)
	}
	conn.Close()
	c.Close()
	var filtered []common.RouterStatus
	for _, v := range cns.RelayInformation {
		if !v.StatusFlags[common.FLAG_V2DIR] ||
			!v.StatusFlags[common.FLAG_FAST] ||
			!v.StatusFlags[common.FLAG_STABLE] ||
			!v.StatusFlags[common.FLAG_VALID] ||
			v.StatusFlags[common.FLAG_AUTHORITY] {
			continue
		}
		filtered = append(filtered, v)
	}
	fmt.Printf("Got %d relays matching the filter. Randomly sampling %d...\n", len(filtered), NumberOfRelays)
	if len(filtered) < NumberOfRelays {
		fmt.Fprintln(os.Stderr, "Not enough relays matching our filter")
		os.Exit(1)
	}

	var picks []common.RouterStatus
	lookup := make(map[int]struct{})

	for len(picks) != 200 {
		i := rand.IntN(len(filtered))
		if _, exists := lookup[i]; exists {
			continue
		}

		picks = append(picks, filtered[i])
		lookup[i] = struct{}{}
	}

	goDirsFile, err := os.OpenFile("tor-gonion_fallback_dirs.go", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		panic(err)
	}
	defer goDirsFile.Close()

	writeHeaderToFile(goDirsFile)
	writeGoFormat(picks, goDirsFile)

}
