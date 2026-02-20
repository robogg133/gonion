package shared

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	PARSER_STATE_HEADER uint8 = iota
	PARSER_STATE_DIRS
	PARSER_STATE_ROUTERS
	PARSER_STATE_FOOTER
)

const CONSENSUS_DATE_FORMAT string = "2006-01-02 15:04:05"

var errUnknownToken = errors.New("uknown token")

func ParseConsensus(scanner *bufio.Scanner) (*Consensus, error) {

	var consensus Consensus

	currentState := PARSER_STATE_HEADER

	line := 1
	for scanner.Scan() {
		s := scanner.Text()

	switchAgain:
		switch currentState {

		case PARSER_STATE_HEADER:
			if err := consensus.parseHeaderState(s); err != nil {
				if err != errUnknownToken {
					return nil, err
				}
				currentState = PARSER_STATE_DIRS
				goto switchAgain
			}
		case PARSER_STATE_DIRS:
			if err := consensus.parseDirState(s); err != nil {
				if err != errUnknownToken {
					return nil, err
				}
				currentState = PARSER_STATE_ROUTERS
				goto switchAgain
			}
		case PARSER_STATE_ROUTERS:
			if err := consensus.parseRouterState(s); err != nil {
				if err != errUnknownToken {
					return nil, err
				}
				currentState = PARSER_STATE_FOOTER
				goto switchAgain
			}
		case PARSER_STATE_FOOTER:
			if err := consensus.parseFooterState(s); err != nil {
				return nil, err
			}
		}

		line++
	}

	return &consensus, nil
}

/*
valid-after 2026-01-30 22:00:00
fresh-until 2026-01-30 23:00:00
valid-until 2026-01-31 01:00:00
*/
func (c *Consensus) parseHeaderState(s string) error {
	switch {
	case strings.HasPrefix(s, "valid-after "):
		s = strings.TrimPrefix(s, "valid-after ")

		c.ValidAfter, _ = time.Parse(CONSENSUS_DATE_FORMAT, s)

		return nil
	case strings.HasPrefix(s, "fresh-until "):
		s = strings.TrimPrefix(s, "fresh-until ")

		var err error
		c.FreshUntil, err = time.Parse(CONSENSUS_DATE_FORMAT, s)

		if err != nil {
			return err
		}

		return nil
	case strings.HasPrefix(s, "valid-until "):
		s = strings.TrimPrefix(s, "valid-until ")

		c.ValidUntil, _ = time.Parse(CONSENSUS_DATE_FORMAT, s)

		return nil
	case strings.HasPrefix(s, "network-status-version "):
		s = strings.TrimPrefix(s, "network-status-version ")
		if s == "3" {
			c.NetowrkStatusVersion = 3
		}

		return nil

	case strings.HasPrefix(s, "shared-rand-current-value "):
		s = strings.TrimPrefix(s, "shared-rand-current-value ")

		sep := strings.Split(s, " ")

		n, err := strconv.Atoi(sep[0])
		if err != nil {
			return err
		}

		if uint8(n) >= AUTH_DIR_NUM_AGREEMENTS {

			a, err := base64.StdEncoding.DecodeString(sep[1])
			if err != nil {
				return err
			}
			c.SharedCurrentValue = [32]byte(a)
		}

		return nil
	case strings.HasPrefix(s, "dir-source "):
		return errUnknownToken
	default:
		return nil

	}
}

func (c *Consensus) parseRouterState(s string) error {
	switch {
	case strings.HasPrefix(s, "r "):
		s = strings.TrimPrefix(s, "r ")
		if c.routerStatusTmp != nil {
			c.RelayInformation = append(c.RelayInformation, *c.routerStatusTmp)
		} else {
			c.routerStatusTmp = &RouterStatus{}
		}

		separated := strings.Split(s, " ")

		c.routerStatusTmp.Nickname = separated[0]

		b, err := base64.RawStdEncoding.DecodeString(separated[1])
		if err != nil {
			return err
		}
		c.routerStatusTmp.NodeID = [20]byte(b)

		// Ignore 2 and 3 cuz they are timestamps

		c.routerStatusTmp.Ipv4Addr = separated[4]

		c.routerStatusTmp.IPLevel, err = IPLevel(separated[4], 0)
		if err != nil {
			return err
		}

		n, err := strconv.Atoi(separated[5])
		if err != nil {
			return err
		}
		c.routerStatusTmp.ORPort = uint16(n)

		n, err = strconv.Atoi(separated[6])
		if err != nil {
			return err
		}
		c.routerStatusTmp.DirPort = uint16(n)

		return nil
	case strings.HasPrefix(s, "a "):
		s = strings.TrimPrefix(s, "a ")
		c.routerStatusTmp.Ipv6Addr = s

		return nil
	case strings.HasPrefix(s, "s "):
		s = strings.TrimPrefix(s, "s ")

		separated := strings.Split(s, " ")

		for _, v := range separated {
			c.routerStatusTmp.StatusFlags[flagStringToNumber(v)] = true
		}

		return nil

	case strings.HasPrefix(s, "v "):
		return nil

	case strings.HasPrefix(s, "pr "):
		s = strings.TrimPrefix(s, "pr ")

		separated := strings.SplitSeq(s, " ")

		for v := range separated {
			sep := strings.Split(v, "=")

			var versionByte VersionValue

			key := sep[0]

			nums := strings.SplitSeq(sep[1], ",")
			for num := range nums {
				if !strings.Contains(num, "-") {
					n, err := strconv.Atoi(num)
					if err != nil {
						return err
					}
					versionByte.SetValue(uint8(n), true)
				} else {
					start, err := strconv.Atoi(string(num[0]))
					if err != nil {
						return err
					}
					end, err := strconv.Atoi(string(num[2]))
					if err != nil {
						return err
					}

					var i uint8
					for i = uint8(start); i <= uint8(end); i++ {
						versionByte.SetValue(i, true)
					}
				}

			}

			switch key {
			case "Link":
				c.routerStatusTmp.ProtoVersions.Link = versionByte
			case "LinkAuth":
				c.routerStatusTmp.ProtoVersions.LinkAuth = versionByte
			case "Relay":
				c.routerStatusTmp.ProtoVersions.Relay = versionByte
			case "DirCache":
				c.routerStatusTmp.ProtoVersions.DirCache = versionByte
			case "HSDir":
				c.routerStatusTmp.ProtoVersions.HSDir = versionByte
			case "HSIntro":
				c.routerStatusTmp.ProtoVersions.HSIntro = versionByte
			case "HSRend":
				c.routerStatusTmp.ProtoVersions.HSRend = versionByte
			case "Desc":
				c.routerStatusTmp.ProtoVersions.Desc = versionByte
			case "Microdesc":
				c.routerStatusTmp.ProtoVersions.Microdesc = versionByte
			case "Cons":
				c.routerStatusTmp.ProtoVersions.Cons = versionByte
			case "Padding":
				c.routerStatusTmp.ProtoVersions.Padding = versionByte
			case "FlowCtrl":
				c.routerStatusTmp.ProtoVersions.FlowCtrl = versionByte
			case "Conflux":
				c.routerStatusTmp.ProtoVersions.Conflux = versionByte
			}
		}

		return nil

	case strings.HasPrefix(s, "w "):
		s = strings.TrimPrefix(s, "w ")

		s = strings.Split(s, " ")[0]

		n, err := strconv.Atoi(strings.Split(s, "=")[1])
		if err != nil {
			return err
		}
		c.routerStatusTmp.BandWidth = uint32(n)

		return nil
	case strings.HasPrefix(s, "m "):
		s = strings.TrimPrefix(s, "m ")

		c.routerStatusTmp.MicrodescriptorDigest = s
		return nil
	case strings.HasPrefix(s, "p "):
		s = strings.TrimPrefix(s, "p ")

		separated := strings.Split(s, " ")

		if separated[0] == "reject" && separated[1] == "1-65535" {
			c.routerStatusTmp.Ports = Ports{}
			return nil
		} else if separated[0] == "accept" && separated[1] == "1-65535" {
			c.routerStatusTmp.Ports.turnOnAllPorts()
			return nil
		}

		switch separated[0] {
		case "reject":
			p, err := parseReject(separated[1])
			if err != nil {
				return err
			}
			c.routerStatusTmp.Ports = p
		case "accept":
			p, err := parseAccept(separated[1])
			if err != nil {
				return err
			}
			c.routerStatusTmp.Ports = p
		}
		return nil
	default:
		return errUnknownToken

	}
}

func (c *Consensus) parseFooterState(s string) error {

	switch {
	case strings.HasPrefix(s, "bandwidth-weights "):
		s = strings.TrimPrefix(s, "bandwidth-weights ")

		var band BandWidthWeight

		parts := strings.Fields(s)
		for _, p := range parts {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				return fmt.Errorf("invalid bandwidth weight token: %q", p)
			}

			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid bandwidth weight value %q: %w", kv[1], err)
			}

			v := int32(val)

			switch kv[0] {
			case "Wbd":
				band.Wbd = v
			case "Wbe":
				band.Wbe = v
			case "Wbg":
				band.Wbg = v
			case "Wbm":
				band.Wbm = v
			case "Wdb":
				band.Wdb = v
			case "Web":
				band.Web = v
			case "Wed":
				band.Wed = v
			case "Wee":
				band.Wee = v
			case "Weg":
				band.Weg = v
			case "Wem":
				band.Wem = v
			case "Wgb":
				band.Wgb = v
			case "Wgd":
				band.Wgd = v
			case "Wgg":
				band.Wgg = v
			case "Wgm":
				band.Wgm = v
			case "Wmb":
				band.Wmb = v
			case "Wmd":
				band.Wmd = v
			case "Wme":
				band.Wme = v
			case "Wmg":
				band.Wmg = v
			case "Wmm":
				band.Wmm = v
			default:
				return fmt.Errorf("unknown bandwidth weight key: %s", kv[0])
			}
		}

		c.BandWidthWeight = band
		return nil
	}

	return nil
}

func (c *Consensus) parseDirState(s string) error {

	if strings.HasPrefix(s, "r ") {
		return errUnknownToken
	}

	return nil
}

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

		p24 := uint32(ip4[0])<<16 |
			uint32(ip4[1])<<8 |
			uint32(ip4[2])

		return uint32(LEVEL_P24<<28) | p24, nil
	}

	ip = ip.To16()
	if ip == nil {
		return 0, fmt.Errorf("invalid IP")
	}

	var v uint32
	for i := 0; i < 4; i++ {
		v = (v << 8) | uint32(ip[i])
	}

	return uint32(LEVEL_IPV6<<28) | v, nil
}
