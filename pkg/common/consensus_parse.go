package common

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Parse retains the original signed document. Structural validity is not trust.
func ParseConsensus(r io.Reader) (*Consensus, error) {
	data, err := ReadDirectoryDocument(r, MaxConsensusSize)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("consensus: missing final newline")
	}
	c, err := parseConsensus(bufio.NewScanner(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	c.RawDocument = data
	return c, nil
}

func parseConsensus(scanner *bufio.Scanner) (*Consensus, error) {
	c := &Consensus{}
	seen := make(map[string]bool)
	var router *RouterStatus
	var routerSeen map[string]bool
	footer, signatures := false, 0
	finishRouter := func() error {
		if router == nil {
			return nil
		}
		if !routerSeen["s"] || (c.Flavor == ConsensusFlavorMicrodesc && !routerSeen["m"]) {
			return fmt.Errorf("consensus: incomplete router status")
		}
		if len(c.RelayInformation) >= MaxConsensusRelays {
			return fmt.Errorf("consensus: too many relays")
		}
		c.RelayInformation = append(c.RelayInformation, *router)
		router = nil
		return nil
	}
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) == 0 {
			continue
		}
		key := f[0]
		if !seen["network-status-version"] && key != "network-status-version" {
			return nil, fmt.Errorf("consensus: missing initial network-status-version")
		}
		switch key {
		case "network-status-version", "vote-status", "valid-after", "fresh-until", "valid-until", "shared-rand-current-value", "shared-rand-previous-value", "params":
			if router != nil || footer || len(c.RelayInformation) != 0 || seen[key] {
				return nil, fmt.Errorf("consensus: misplaced or duplicate %s", key)
			}
			seen[key] = true
			if err := parseHeader(c, f); err != nil {
				return nil, err
			}
		case "r":
			if footer {
				return nil, fmt.Errorf("consensus: router after footer")
			}
			if err := finishRouter(); err != nil {
				return nil, err
			}
			var err error
			router, err = parseRouter(c.Flavor, f)
			if err != nil {
				return nil, err
			}
			routerSeen = make(map[string]bool)
		case "a", "s", "v", "pr", "w", "m", "p":
			if router == nil || footer {
				return nil, fmt.Errorf("consensus: %s outside router status", key)
			}
			if key != "a" && routerSeen[key] {
				return nil, fmt.Errorf("consensus: duplicate router %s", key)
			}
			routerSeen[key] = true
			if err := parseRouterItem(c.Flavor, router, f); err != nil {
				return nil, err
			}
		case "directory-footer":
			if footer || len(f) != 1 {
				return nil, fmt.Errorf("consensus: invalid directory-footer")
			}
			if err := finishRouter(); err != nil {
				return nil, err
			}
			footer = true
			// Resolve absent weights here, while preserving an explicit zero.
			weights := reflect.ValueOf(&c.BandWidthWeight).Elem()
			for i := 0; i < weights.NumField(); i++ {
				weights.Field(i).SetInt(int64(c.Parameter("bwweightscale", 10000, 1, 1<<31-1)))
			}
		case "bandwidth-weights":
			if !footer || signatures != 0 || seen[key] {
				return nil, fmt.Errorf("consensus: misplaced bandwidth-weights")
			}
			seen[key] = true
			weights := reflect.ValueOf(&c.BandWidthWeight).Elem()
			weightSeen := make(map[string]bool)
			for _, item := range f[1:] {
				k, v, ok := strings.Cut(item, "=")
				if weightSeen[k] {
					return nil, fmt.Errorf("consensus: duplicate bandwidth weight %q", k)
				}
				weightSeen[k] = true
				n, err := strconv.ParseInt(v, 10, 32)
				// path-spec 2.2 defaults missing/malformed weights; C Tor caps
				// positive weights at bwweightscale (networkstatus_get_bw_weight).
				if !ok || err != nil || n < 0 {
					continue
				}
				field := weights.FieldByName(k)
				if field.IsValid() {
					field.SetInt(min(n, int64(c.Parameter("bwweightscale", 10000, 1, 1<<31-1))))
				}
			}
		case "directory-signature":
			if !footer {
				return nil, fmt.Errorf("consensus: signature before footer")
			}
			if err := parseSignature(scanner, c.Flavor, f); err != nil {
				return nil, err
			}
			signatures++
		default:
			// Unknown keywords do not end the current section (dir-spec 1.2).
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("consensus: read: %w", err)
	}
	if !footer || signatures == 0 {
		return nil, fmt.Errorf("consensus: missing footer or signatures")
	}
	for _, key := range []string{"network-status-version", "vote-status", "valid-after", "fresh-until", "valid-until"} {
		if !seen[key] {
			return nil, fmt.Errorf("consensus: missing %s", key)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func parseHeader(c *Consensus, f []string) error {
	if len(f) < 2 && f[0] != "params" {
		return fmt.Errorf("consensus: missing %s arguments", f[0])
	}
	switch f[0] {
	case "network-status-version":
		if f[1] != "3" {
			return fmt.Errorf("consensus: unsupported version %q", f[1])
		}
		c.NetowrkStatusVersion, c.Flavor = 3, ConsensusFlavorNS
		if len(f) > 2 {
			c.Flavor = f[2]
		}
		if c.Flavor != ConsensusFlavorNS && c.Flavor != ConsensusFlavorMicrodesc {
			return fmt.Errorf("consensus: unsupported flavor %q", c.Flavor)
		}
	case "vote-status":
		if f[1] != "consensus" {
			return fmt.Errorf("consensus: votes are not consensuses")
		}
	case "valid-after", "fresh-until", "valid-until":
		if len(f) < 3 {
			return fmt.Errorf("consensus: missing timestamp")
		}
		t, err := time.Parse(CONSENSUS_DATE_FORMAT, f[1]+" "+f[2])
		if err != nil {
			return err
		}
		switch f[0] {
		case "valid-after":
			c.ValidAfter = t
		case "fresh-until":
			c.FreshUntil = t
		case "valid-until":
			c.ValidUntil = t
		}
	case "shared-rand-current-value", "shared-rand-previous-value":
		if len(f) < 3 {
			return fmt.Errorf("consensus: missing shared random value")
		}
		if _, err := strconv.ParseUint(f[1], 10, 32); err != nil {
			return fmt.Errorf("consensus: invalid reveal count")
		}
		b, err := base64.StdEncoding.Strict().DecodeString(f[2])
		if err != nil || len(b) != 32 {
			return fmt.Errorf("consensus: invalid shared random value")
		}
		// NumReveals is not an authority signature count.
		if f[0] == "shared-rand-current-value" {
			copy(c.SharedCurrentValue[:], b)
			c.HasSharedCurrentValue = true
		} else {
			copy(c.SharedPreviousValue[:], b)
			c.HasSharedPreviousValue = true
		}
	case "params":
		c.Params = make(map[string]int32)
		for _, item := range f[1:] {
			k, v, ok := strings.Cut(item, "=")
			n, err := strconv.ParseInt(v, 10, 32)
			if !ok || err != nil {
				return fmt.Errorf("consensus: invalid parameter %q", item)
			}
			if _, duplicate := c.Params[k]; duplicate {
				return fmt.Errorf("consensus: duplicate parameter")
			}
			c.Params[k] = int32(n)
			if k == "hsdir_interval" {
				if n <= 0 {
					return fmt.Errorf("consensus: invalid hsdir_interval")
				}
				value := uint64(n)
				c.HsdirInterval = &value
			}
		}
	}
	return nil
}

func parseRouter(flavor string, f []string) (*RouterStatus, error) {
	offset := 0
	if flavor == ConsensusFlavorNS {
		offset = 1
	}
	if len(f) < 8+offset {
		return nil, fmt.Errorf("consensus: malformed %s router line", flavor)
	}
	r := &RouterStatus{Nickname: f[1], Ipv4Addr: f[5+offset]}
	if len(r.Nickname) == 0 || len(r.Nickname) > 19 || strings.IndexFunc(r.Nickname, func(c rune) bool { return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') }) >= 0 {
		return nil, fmt.Errorf("consensus: invalid nickname")
	}
	b, err := base64.RawStdEncoding.Strict().DecodeString(f[2])
	if err != nil || len(b) != 20 {
		return nil, fmt.Errorf("consensus: invalid relay identity")
	}
	copy(r.NodeID[:], b)
	if offset == 1 {
		r.DescriptorDigest = f[3]
	}
	ip, err := netip.ParseAddr(r.Ipv4Addr)
	if err != nil || !ip.Is4() {
		return nil, fmt.Errorf("consensus: invalid IPv4 address")
	}
	r.IPLevel, err = IPLevel(r.Ipv4Addr, 0)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(f[6+offset], 10, 16)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("consensus: invalid OR port")
	}
	r.ORPort = uint16(n)
	n, err = strconv.ParseUint(f[7+offset], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("consensus: invalid directory port")
	}
	r.DirPort = uint16(n)
	return r, nil
}

var flagNames = []string{"Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "MiddleOnly", "NoEdConsensus", "Stable", "StaleDesc", "Running", "Valid", "V2Dir", "Sybil"}

func parseRouterItem(flavor string, r *RouterStatus, f []string) error {
	switch f[0] {
	case "a":
		if len(f) < 2 {
			return fmt.Errorf("consensus: missing OR address")
		}
		a, err := netip.ParseAddrPort(f[1])
		if err != nil || a.Port() == 0 {
			return fmt.Errorf("consensus: invalid OR address")
		}
		if a.Addr().Is6() && r.Ipv6Addr == "" {
			r.Ipv6Addr = f[1]
		}
	case "s":
		for _, flag := range f[1:] {
			for i, known := range flagNames {
				if flag == known {
					r.StatusFlags[i] = true
					break
				}
			}
		}
	case "m":
		if flavor != ConsensusFlavorMicrodesc || len(f) < 2 {
			return fmt.Errorf("consensus: unexpected microdescriptor digest")
		}
		r.MicrodescriptorDigest = f[1]
	case "p":
		return ParseDirectoryPorts(&r.Ports, strings.Join(f[1:], " "))
	case "w":
		for _, item := range f[1:] {
			k, v, ok := strings.Cut(item, "=")
			if !ok {
				return fmt.Errorf("consensus: invalid bandwidth token")
			}
			if k == "Bandwidth" {
				n, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return err
				}
				r.BandWidth = uint32(n)
			}
		}
	case "pr":
		proto := reflect.ValueOf(&r.ProtoVersions).Elem()
		for _, item := range f[1:] {
			k, v, ok := strings.Cut(item, "=")
			if !ok {
				return fmt.Errorf("consensus: malformed protocol entry")
			}
			var bits VersionValue
			if v != "" {
				for _, part := range strings.Split(v, ",") {
					a, b, ranged := strings.Cut(part, "-")
					start, err := strconv.ParseUint(a, 10, 6)
					if err != nil {
						return fmt.Errorf("consensus: invalid protocol version")
					}
					end := start
					if ranged {
						end, err = strconv.ParseUint(b, 10, 6)
						if err != nil || end < start {
							return fmt.Errorf("consensus: invalid protocol range")
						}
					}
					// The existing API stores only versions 0..7. Never wrap a higher
					// version into a supported bit; widening the model is separate work.
					for n := start; n <= end && n < 8; n++ {
						bits.SetValue(uint8(n), true)
					}
				}
			}
			field := proto.FieldByName(k)
			if field.IsValid() {
				field.SetUint(uint64(bits))
			}
		}
	}
	return nil
}

func parseSignature(scanner *bufio.Scanner, flavor string, f []string) error {
	start, algorithm := 1, "sha1"
	if len(f) >= 4 {
		start, algorithm = 2, f[1]
	}
	if len(f) < start+2 {
		return fmt.Errorf("consensus: malformed signature header")
	}
	if flavor == ConsensusFlavorNS && algorithm != "sha1" {
		return fmt.Errorf("consensus: non-SHA1 ns signature")
	}
	for _, value := range f[start : start+2] {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 20 {
			return fmt.Errorf("consensus: invalid signature key digest")
		}
	}
	var b bytes.Buffer
	if !scanner.Scan() || scanner.Text() != "-----BEGIN SIGNATURE-----" {
		return fmt.Errorf("consensus: missing signature object")
	}
	b.WriteString(scanner.Text() + "\n")
	for scanner.Scan() {
		b.WriteString(scanner.Text() + "\n")
		if b.Len() > 16<<10 {
			return fmt.Errorf("consensus: signature object too large")
		}
		if scanner.Text() == "-----END SIGNATURE-----" {
			block, rest := pem.Decode(b.Bytes())
			if block == nil || len(rest) != 0 || len(block.Bytes) < 128 {
				return fmt.Errorf("consensus: invalid signature object")
			}
			return nil
		}
	}
	return fmt.Errorf("consensus: truncated signature object")
}

// Format returns the original document, never a synthetic unsigned consensus.
// Changes to the parsed model are not serialized here; use the JSON snapshot
// parser to persist hydration and other local fields.
func FormatConsensus(c *Consensus) ([]byte, error) {
	if c == nil || len(c.RawDocument) == 0 {
		return nil, fmt.Errorf("consensus: original signed document is unavailable")
	}
	parsed, err := ParseConsensus(bytes.NewReader(c.RawDocument))
	if err != nil {
		return nil, err
	}
	if parsed.Flavor != c.Flavor || !parsed.ValidAfter.Equal(c.ValidAfter) || !parsed.FreshUntil.Equal(c.FreshUntil) || !parsed.ValidUntil.Equal(c.ValidUntil) {
		return nil, fmt.Errorf("consensus: original document metadata mismatch")
	}
	return bytes.Clone(c.RawDocument), nil
}
