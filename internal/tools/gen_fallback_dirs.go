//go:build fallback

package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const TOR_FALLBACK_DIRS_INC_GITLAB_RAW string = "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc?ref_type=heads&inline=false"

type Fallback struct {
	IPv4, Fingerprint, IPv6, Nickname string
	ORPort, IPv6Port                  uint16
}

func main() {

	in, err := http.Get(TOR_FALLBACK_DIRS_INC_GITLAB_RAW)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Body.Close()

	var entries []Fallback
	var cur *Fallback

	scanner := bufio.NewScanner(in.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, `"`) && strings.Contains(line, "orport=") {
			cur = &Fallback{}
			line = strings.Trim(line, `"`)
			parts := strings.Fields(line)

			cur.IPv4 = parts[0]

			for _, p := range parts {
				if a, found := strings.CutPrefix(p, "orport="); found {
					port, _ := strconv.Atoi(a)
					cur.ORPort = uint16(port)
				}
				if a, found := strings.CutPrefix(p, "id="); found {
					cur.Fingerprint = a
				}
			}
			continue
		}

		// ipv6
		if cur != nil && strings.Contains(line, "ipv6=") {
			line = strings.Trim(line, `"`)
			l := strings.Split(line, "[")
			r := strings.Split(l[1], "]")
			cur.IPv6 = r[0]

			p, _ := strconv.Atoi(strings.TrimPrefix(r[1], ":"))
			cur.IPv6Port = uint16(p)
			continue
		}

		// nickname
		if cur != nil && strings.Contains(line, "nickname=") {
			cur.Nickname = strings.TrimSuffix(
				strings.TrimPrefix(line, "/* nickname="),
				" */",
			)
			continue
		}

		// end
		if cur != nil && strings.Contains(line, "=====") {
			entries = append(entries, *cur)
			cur = nil
		}
	}

	fmt.Printf("/* timestamp=%d */\n", time.Now().UTC().Unix())
	fmt.Println("//")
	fmt.Printf("// Generated on: %s\n\n", time.Now().String())

	fmt.Println("package shared\n")
	fmt.Println("type FallbackDir struct {")
	fmt.Println("\tIPv4 string")
	fmt.Println("\tORPort uint16")
	fmt.Println("\tFingerprint string")
	fmt.Println("\tIPv6 string // empty string if don't")
	fmt.Println("\tIPv6Port uint16 // 0 if don't")
	fmt.Println("\tNickname string")
	fmt.Println("}\n")
	fmt.Println("var Fallbacks = []FallbackDir{")

	for _, e := range entries {
		fmt.Println("\t{")
		fmt.Printf("\t\tIPv4: \"%s\",\n", e.IPv4)
		fmt.Printf("\t\tORPort: %d,\n", e.ORPort)
		fmt.Printf("\t\tFingerprint: \"%s\",\n", e.Fingerprint)
		if e.IPv6 != "" {
			fmt.Printf("\t\tIPv6: \"%s\",\n", e.IPv6)
			fmt.Printf("\t\tIPv6Port: %d,\n", e.IPv6Port)
		}
		fmt.Printf("\t\tNickname: \"%s\",\n", e.Nickname)
		fmt.Println("\t},")
	}

	fmt.Println("}")
}
