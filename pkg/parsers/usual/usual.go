// Package usual parses and formats the network-status consensus document
// (Tor's "ns" text format).
package usual

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

const (
	PARSER_STATE_HEADER uint8 = iota
	PARSER_STATE_DIRS
	PARSER_STATE_ROUTERS
	PARSER_STATE_FOOTER
)

var errUnknownToken = errors.New("uknown token")

func flagStringToNumber(s string) uint8 {
	//  Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
	switch s {
	case "Authority":
		return 0
	case "BadExit":
		return 1
	case "Exit":
		return 2
	case "Fast":
		return 3
	case "Guard":
		return 4
	case "HSDir":
		return 5
	case "MiddleOnly":
		return 6
	case "NoEdConsensus":
		return 7
	case "Running":
		return 10
	case "Stable":
		return 8
	case "StaleDesc":
		return 9
	case "Sybil":
		return 13
	case "V2Dir":
		return 12
	case "Valid":
		return 11
	default:
		return 15
	}
}

var flagNumberToString = []string{
	"Authority",
	"BadExit",
	"Exit",
	"Fast",
	"Guard",
	"HSDir",
	"MiddleOnly",
	"NoEdConsensus",
	"Stable",
	"StaleDesc",
	"Running",
	"Valid",
	"V2Dir",
	"Sybil",
}

// Parser implements common.ConsensusParser for the usual consensus text format.
type Parser struct{}

func (Parser) Parse(r io.Reader) (*common.Consensus, error) {
	return parseConsensus(bufio.NewScanner(r))
}

func parseConsensus(scanner *bufio.Scanner) (*common.Consensus, error) {
	var consensus common.Consensus

	currentState := PARSER_STATE_HEADER

	var routerStatusTmp *common.RouterStatus

	for scanner.Scan() {
		s := scanner.Text()

	switchAgain:
		switch currentState {

		case PARSER_STATE_HEADER:
			if err := parseHeaderState(&consensus, s); err != nil {
				if err != errUnknownToken {
					return nil, err
				}
				currentState = PARSER_STATE_DIRS
				goto switchAgain
			}
		case PARSER_STATE_DIRS:
			if err := parseDirState(s); err != nil {
				if err != errUnknownToken {
					return nil, err
				}
				currentState = PARSER_STATE_ROUTERS
				goto switchAgain
			}
		case PARSER_STATE_ROUTERS:
			if err := parseRouterState(&consensus, &routerStatusTmp, s); err != nil {
				if err != errUnknownToken {
					return nil, err
				}
				currentState = PARSER_STATE_FOOTER
				goto switchAgain
			}
		case PARSER_STATE_FOOTER:
			if err := parseFooterState(&consensus, s); err != nil {
				return nil, err
			}
		}
	}

	if routerStatusTmp != nil {
		consensus.RelayInformation = append(consensus.RelayInformation, *routerStatusTmp)
	}

	return &consensus, nil
}

/*
valid-after 2026-01-30 22:00:00
fresh-until 2026-01-30 23:00:00
valid-until 2026-01-31 01:00:00
*/
func parseHeaderState(c *common.Consensus, s string) error {
	switch {
	case strings.HasPrefix(s, "valid-after "):
		s = strings.TrimPrefix(s, "valid-after ")

		c.ValidAfter, _ = time.Parse(common.CONSENSUS_DATE_FORMAT, s)

		return nil
	case strings.HasPrefix(s, "fresh-until "):
		s = strings.TrimPrefix(s, "fresh-until ")

		var err error
		c.FreshUntil, err = time.Parse(common.CONSENSUS_DATE_FORMAT, s)

		if err != nil {
			return err
		}

		return nil
	case strings.HasPrefix(s, "valid-until "):
		s = strings.TrimPrefix(s, "valid-until ")

		c.ValidUntil, _ = time.Parse(common.CONSENSUS_DATE_FORMAT, s)

		return nil
	case strings.HasPrefix(s, "network-status-version "):
		s = strings.TrimPrefix(s, "network-status-version ")
		if strings.Split(s, " ")[0] == "3" {
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

		if uint8(n) >= common.AUTH_DIR_NUM_AGREEMENTS {

			a, err := base64.StdEncoding.DecodeString(sep[1])
			if err != nil {
				return err
			}
			c.SharedCurrentValue = [32]byte(a)
		}

		return nil
	case strings.HasPrefix(s, "shared-rand-previous-value "):
		s = strings.TrimPrefix(s, "shared-rand-previous-value ")

		sep := strings.Split(s, " ")

		n, err := strconv.Atoi(sep[0])
		if err != nil {
			return err
		}

		if uint8(n) >= common.AUTH_DIR_NUM_AGREEMENTS {

			a, err := base64.StdEncoding.DecodeString(sep[1])
			if err != nil {
				return err
			}
			c.SharedPreviousValue = [32]byte(a)
		}

		return nil
	case strings.HasPrefix(s, "dir-source "):
		return errUnknownToken
	case strings.HasPrefix(s, "r "):
		return errUnknownToken
	default:
		return nil

	}
}

func parseRouterState(c *common.Consensus, routerStatusTmp **common.RouterStatus, s string) error {
	switch {
	case strings.HasPrefix(s, "r "):
		s = strings.TrimPrefix(s, "r ")
		if *routerStatusTmp != nil {
			c.RelayInformation = append(c.RelayInformation, **routerStatusTmp)
		}
		*routerStatusTmp = &common.RouterStatus{}

		separated := strings.Split(s, " ")
		// When the stream is truncated (e.g. due to circuit DESTROY),
		// router lines may be malformed and contain too few tokens.
		// Avoid panics; return an error so callers can retry/abort.
		if len(separated) < 7 {
			return fmt.Errorf("consensus: router_state: malformed router line: %q", s)
		}

		(*routerStatusTmp).Nickname = separated[0]

		b, err := base64.RawStdEncoding.DecodeString(separated[1])
		if err != nil {
			return err
		}
		(*routerStatusTmp).NodeID = [20]byte(b)

		// Ignore 2 and 3 cuz they are timestamps

		(*routerStatusTmp).Ipv4Addr = separated[4]

		(*routerStatusTmp).IPLevel, err = common.IPLevel(separated[4], 0)
		if err != nil {
			return err
		}

		n, err := strconv.Atoi(separated[5])
		if err != nil {
			return err
		}
		(*routerStatusTmp).ORPort = uint16(n)

		n, err = strconv.Atoi(separated[6])
		if err != nil {
			return err
		}
		(*routerStatusTmp).DirPort = uint16(n)

		return nil
	case strings.HasPrefix(s, "a "):
		s = strings.TrimPrefix(s, "a ")
		(*routerStatusTmp).Ipv6Addr = s

		return nil
	case strings.HasPrefix(s, "s "):
		s = strings.TrimPrefix(s, "s ")

		separated := strings.Split(s, " ")

		for _, v := range separated {
			(*routerStatusTmp).StatusFlags[flagStringToNumber(v)] = true
		}

		return nil

	case strings.HasPrefix(s, "v "):
		return nil

	case strings.HasPrefix(s, "pr "):
		s = strings.TrimPrefix(s, "pr ")

		separated := strings.SplitSeq(s, " ")

		for v := range separated {
			sep := strings.Split(v, "=")
			if len(sep) < 2 {
				return fmt.Errorf("consensus: router_state: malformed pr line: %q", s)
			}

			var versionByte common.VersionValue

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
				(*routerStatusTmp).ProtoVersions.Link = versionByte
			case "LinkAuth":
				(*routerStatusTmp).ProtoVersions.LinkAuth = versionByte
			case "Relay":
				(*routerStatusTmp).ProtoVersions.Relay = versionByte
			case "DirCache":
				(*routerStatusTmp).ProtoVersions.DirCache = versionByte
			case "HSDir":
				(*routerStatusTmp).ProtoVersions.HSDir = versionByte
			case "HSIntro":
				(*routerStatusTmp).ProtoVersions.HSIntro = versionByte
			case "HSRend":
				(*routerStatusTmp).ProtoVersions.HSRend = versionByte
			case "Desc":
				(*routerStatusTmp).ProtoVersions.Desc = versionByte
			case "Microdesc":
				(*routerStatusTmp).ProtoVersions.Microdesc = versionByte
			case "Cons":
				(*routerStatusTmp).ProtoVersions.Cons = versionByte
			case "Padding":
				(*routerStatusTmp).ProtoVersions.Padding = versionByte
			case "FlowCtrl":
				(*routerStatusTmp).ProtoVersions.FlowCtrl = versionByte
			case "Conflux":
				(*routerStatusTmp).ProtoVersions.Conflux = versionByte
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
		(*routerStatusTmp).BandWidth = uint32(n)

		return nil
	case strings.HasPrefix(s, "m "):
		s = strings.TrimPrefix(s, "m ")

		(*routerStatusTmp).MicrodescriptorDigest = s
		return nil
	case strings.HasPrefix(s, "p "):
		s = strings.TrimPrefix(s, "p ")

		return common.ParsePortsLine(&(*routerStatusTmp).Ports, s)
	default:
		return errUnknownToken
	}
}

func parseFooterState(c *common.Consensus, s string) error {

	switch {
	case strings.HasPrefix(s, "bandwidth-weights "):
		s = strings.TrimPrefix(s, "bandwidth-weights ")

		var band common.BandWidthWeight

		parts := strings.Fields(s)
		for _, p := range parts {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				return fmt.Errorf("consensus: footer_state: invalid bandwidth weight token: %q", p)
			}

			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return fmt.Errorf("consensus: footer_state: invalid bandwidth weight value %q: %w", kv[1], err)
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
				return fmt.Errorf("consensus: footer_state: unknown bandwidth weight key: %s", kv[0])
			}
		}

		c.BandWidthWeight = band
		return nil
	}

	return nil
}

func parseDirState(s string) error {

	if strings.HasPrefix(s, "r ") {
		return errUnknownToken
	}

	return nil
}

// Format renders the consensus back into network-status text.
func (Parser) Format(c *common.Consensus) ([]byte, error) {
	var b bytes.Buffer
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	w("network-status-version %d", c.NetowrkStatusVersion)
	w("valid-after %s", c.ValidAfter.Format(common.CONSENSUS_DATE_FORMAT))
	w("fresh-until %s", c.FreshUntil.Format(common.CONSENSUS_DATE_FORMAT))
	w("valid-until %s", c.ValidUntil.Format(common.CONSENSUS_DATE_FORMAT))
	if c.SharedCurrentValue != [32]byte{} {
		w("shared-rand-current-value %d %s", common.AUTH_DIR_NUM_AGREEMENTS, base64.StdEncoding.EncodeToString(c.SharedCurrentValue[:]))
	}

	for i := range c.RelayInformation {
		rs := &c.RelayInformation[i]
		w("r %s %s 1970-01-01 00:00:00 %s %d %d",
			rs.Nickname, base64.RawStdEncoding.EncodeToString(rs.NodeID[:]), rs.Ipv4Addr, rs.ORPort, rs.DirPort)
		if rs.Ipv6Addr != "" {
			w("a %s", rs.Ipv6Addr)
		}
		if flags := flagsLine(rs); flags != "" {
			w("s %s", flags)
		}
		if pr := protoLine(&rs.ProtoVersions); pr != "" {
			w("pr %s", pr)
		}
		w("w Bandwidth=%d", rs.BandWidth)
		if rs.MicrodescriptorDigest != "" {
			w("m %s", rs.MicrodescriptorDigest)
		}
		w("p %s", common.FormatPortsPolicy(&rs.Ports))
	}

	var sb strings.Builder
	sb.WriteString("bandwidth-weights")
	writeWeight(&sb, &c.BandWidthWeight)
	w("%s", sb.String())

	return b.Bytes(), nil
}

func flagsLine(rs *common.RouterStatus) string {
	var sb strings.Builder
	for i, on := range rs.StatusFlags {
		if !on {
			continue
		}
		if i >= len(flagNumberToString) {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(flagNumberToString[i])
	}
	return sb.String()
}

func writeWeight(sb *strings.Builder, bw *common.BandWidthWeight) {
	for _, kv := range [][2]any{
		{"Wbd", bw.Wbd}, {"Wbe", bw.Wbe}, {"Wbg", bw.Wbg}, {"Wbm", bw.Wbm},
		{"Wdb", bw.Wdb}, {"Web", bw.Web}, {"Wed", bw.Wed}, {"Wee", bw.Wee},
		{"Weg", bw.Weg}, {"Wem", bw.Wem}, {"Wgb", bw.Wgb}, {"Wgd", bw.Wgd},
		{"Wgg", bw.Wgg}, {"Wgm", bw.Wgm}, {"Wmb", bw.Wmb}, {"Wmd", bw.Wmd},
		{"Wme", bw.Wme}, {"Wmg", bw.Wmg}, {"Wmm", bw.Wmm},
	} {
		fmt.Fprintf(sb, " %s=%d", kv[0], kv[1])
	}
}

func protoLine(pr *common.Proto) string {
	var sb strings.Builder
	for _, kv := range [][2]any{
		{"Link", pr.Link}, {"LinkAuth", pr.LinkAuth}, {"Relay", pr.Relay},
		{"DirCache", pr.DirCache}, {"HSDir", pr.HSDir}, {"HSIntro", pr.HSIntro},
		{"HSRend", pr.HSRend}, {"Desc", pr.Desc}, {"Microdesc", pr.Microdesc},
		{"Cons", pr.Cons}, {"Padding", pr.Padding}, {"FlowCtrl", pr.FlowCtrl},
		{"Conflux", pr.Conflux},
	} {
		v := kv[1].(common.VersionValue)
		if v == 0 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%s=%s", kv[0], versionValues(v))
	}
	return sb.String()
}

func versionValues(v common.VersionValue) string {
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if v.CheckIsTrue(uint8(i)) {
			if sb.Len() > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "%d", i)
		}
	}
	return sb.String()
}
