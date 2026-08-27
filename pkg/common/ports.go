package common

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func parseReject(s string) (Ports, error) {
	var p Ports

	p.turnOnAllPorts()

	separated := strings.SplitSeq(s, ",")

	for v := range separated {
		if !strings.Contains(v, "-") {
			n, err := strconv.Atoi(v)
			if err != nil {
				return Ports{}, err
			}
			p.SetPort(uint16(n), false)
		} else {
			sep := strings.Split(v, "-")

			start, err := strconv.Atoi(sep[0])
			if err != nil {
				return Ports{}, err
			}
			end, err := strconv.Atoi(sep[1])
			if err != nil {
				return Ports{}, err
			}

			for i := start; i <= end; i++ {
				p.SetPort(uint16(i), false)
			}
		}
	}

	return p, nil
}

func parseAccept(s string) (Ports, error) {
	var p Ports

	separated := strings.SplitSeq(s, ",")

	for v := range separated {
		if !strings.Contains(v, "-") {
			n, err := strconv.Atoi(v)
			if err != nil {
				return Ports{}, err
			}
			p.SetPort(uint16(n), true)
		} else {
			sep := strings.Split(v, "-")

			start, err := strconv.Atoi(sep[0])
			if err != nil {
				return Ports{}, err
			}
			end, err := strconv.Atoi(sep[1])
			if err != nil {
				return Ports{}, err
			}

			for i := start; i <= end; i++ {
				p.SetPort(uint16(i), true)
			}
		}
	}

	return p, nil
}

// ParsePortsLine parses a "reject/accept" policy line, e.g. "accept 20-21,23".
func ParsePortsLine(dst *Ports, s string) error {
	separated := strings.Split(s, " ")

	if separated[0] == "reject" && separated[1] == "1-65535" {
		*dst = Ports{}
		return nil
	} else if separated[0] == "accept" && separated[1] == "1-65535" {
		dst.turnOnAllPorts()
		return nil
	}

	switch separated[0] {
	case "reject":
		p, err := parseReject(separated[1])
		if err != nil {
			return err
		}
		*dst = p
	case "accept":
		p, err := parseAccept(separated[1])
		if err != nil {
			return err
		}
		*dst = p
	}
	return nil
}

// FormatPortsPolicy renders a Ports bitmap back into a policy line
// (the part after "p ", without the leading keyword-less "p").
func FormatPortsPolicy(p *Ports) string {
	allOff, allOn := true, true
	for i := 0; i <= 65535; i++ {
		on := p.IsAllowed(uint16(i))
		if on {
			allOff = false
		} else {
			allOn = false
		}
	}
	if allOff {
		return "reject 1-65535"
	}
	if allOn {
		return "accept 1-65535"
	}

	var sb strings.Builder
	sb.WriteString("accept ")
	first := true
	start := -1
	flush := func(end int) {
		if !first {
			sb.WriteByte(',')
		}
		first = false
		if start == end {
			fmt.Fprintf(&sb, "%d", start)
		} else {
			fmt.Fprintf(&sb, "%d-%d", start, end)
		}
	}
	for i := 0; i <= 65535; i++ {
		if p.IsAllowed(uint16(i)) {
			if start < 0 {
				start = i
			}
		} else if start >= 0 {
			flush(i - 1)
			start = -1
		}
	}
	if start >= 0 {
		flush(65535)
	}
	return sb.String()
}

const (
	LEVEL_ASN  = 1
	LEVEL_P24  = 2
	LEVEL_P16  = 3
	LEVEL_IPV6 = 4
)

func IPLevel(ipStr string, asn uint32) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP")
	}

	if ip4 := ip.To4(); ip4 != nil {

		if asn != 0 {
			return uint32(LEVEL_ASN<<28) | (asn & 0x0FFFFFFF), nil
		}

		p24 := uint32(ip4[0])<<8 |
			uint32(ip4[1])

		return uint32(LEVEL_P24<<28) | p24, nil
	}

	ip = ip.To16()
	if ip == nil {
		return 0, fmt.Errorf("invalid IP")
	}

	var v uint32
	for i := range 4 {
		v = (v << 8) | uint32(ip[i])
	}

	return uint32(LEVEL_IPV6<<28) | v, nil
}