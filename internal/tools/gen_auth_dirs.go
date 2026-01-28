//go:build auth

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

const TOR_AUTH_DIRS_INC_GITLAB_RAW string = "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/auth_dirs.inc?ref_type=heads&inline=false"

type Authority struct {
	Nickname    string
	IPv4        string
	DirPort     uint16
	ORPort      uint16
	IPv6        string
	IPv6Port    uint16
	V3Ident     string
	Fingerprint string
	IsBridge    bool
}

func cleanHex(s string) string {
	return strings.ReplaceAll(s, " ", "")
}

func main() {
	in, err := http.Get(TOR_AUTH_DIRS_INC_GITLAB_RAW)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Body.Close()

	var list []Authority
	var cur *Authority

	scanner := bufio.NewScanner(in.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.Trim(line, `",`)

		if line == "" {
			continue
		}

		if !strings.Contains(line, ":") && strings.Contains(line, "orport=") {
			cur = &Authority{}
			parts := strings.Fields(line)

			cur.Nickname = parts[0]

			for _, p := range parts {
				if strings.HasPrefix(p, "orport=") {
					v, _ := strconv.Atoi(strings.TrimPrefix(p, "orport="))
					cur.ORPort = uint16(v)
				}
				if p == "bridge" {
					cur.IsBridge = true
				}
			}
			continue
		}

		// v3ident
		if cur != nil && strings.HasPrefix(line, "v3ident=") {
			cur.V3Ident = strings.TrimPrefix(line, "v3ident=")
			continue
		}

		// ipv6
		if cur != nil && strings.HasPrefix(line, "ipv6=") {
			v := strings.TrimPrefix(line, "ipv6=")
			v = strings.Trim(v, "[]")

			parts := strings.Split(v, "]:")
			cur.IPv6 = parts[0]
			p, _ := strconv.Atoi(parts[1])
			cur.IPv6Port = uint16(p)
			continue
		}

		// IPv4:DirPort + fingerprint
		if cur != nil && strings.Contains(line, ":") {
			parts := strings.Fields(line)

			ipPort := strings.Split(parts[0], ":")
			cur.IPv4 = ipPort[0]

			p, _ := strconv.Atoi(ipPort[1])
			cur.DirPort = uint16(p)

			cur.Fingerprint = cleanHex(strings.Join(parts[1:], " "))
			list = append(list, *cur)
			cur = nil
		}
	}

	fmt.Printf("/* timestamp=%d */\n", time.Now().UTC().Unix())
	fmt.Println("//")
	fmt.Printf("// Generated on: %s\n\n", time.Now().String())

	fmt.Println("package shared\n")
	fmt.Println("type DirectoryAuthority struct {")
	fmt.Println("\tNickname string")
	fmt.Println("\tIPv4 string")
	fmt.Println("\tDirPort uint16")
	fmt.Println("\tORPort uint16")
	fmt.Println("\tIPv6 string")
	fmt.Println("\tIPv6Port uint16")
	fmt.Println("\tV3Ident string // Ed25519, hex (64 chars)")
	fmt.Println("\tFingerprint string // RSA identity, hex (40 chars)")
	fmt.Println("\tIsBridge bool")
	fmt.Println("}\n")

	fmt.Println("var Authorities = []DirectoryAuthority{")
	for _, a := range list {
		fmt.Println("\t{")
		fmt.Printf("\t\tNickname: \"%s\",\n", a.Nickname)
		fmt.Printf("\t\tORPort: %d,\n", a.ORPort)
		fmt.Printf("\t\tIPv4: \"%s\",\n", a.IPv4)
		fmt.Printf("\t\tDirPort: %d,\n", a.DirPort)
		if a.IPv6 != "" {
			fmt.Printf("\t\tIPv6: \"%s\",\n", a.IPv6)
			fmt.Printf("\t\tIPv6Port: %d,\n", a.IPv6Port)
		}
		if a.V3Ident != "" {
			fmt.Printf("\t\tV3Ident: \"%s\",\n", a.V3Ident)
		}
		fmt.Printf("\t\tFingerprint: \"%s\",\n", a.Fingerprint)
		if a.IsBridge {
			fmt.Println("\t\tIsBridge: true,")
		}
		fmt.Println("\t},")
	}
	fmt.Println("}")
}
