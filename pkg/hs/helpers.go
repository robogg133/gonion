package hs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/hs/desc"
	"github.com/robogg133/gonion/pkg/lspec"
)

// circuitID is a process-wide counter for hidden-service circuits.
var circuitID atomic.Uint32

func nextCircuitID() uint32 { return circuitID.Add(1) }

// clientSRV synchronizes a time period with its SRV (rend-spec-v3 CLIENTFETCH).
func clientSRV(cns *common.Consensus, period, length uint64) [32]byte {
	votingSeconds := cns.CalcSrvVotingInterval() * 60
	seconds := uint64(cns.ValidAfter.Unix())
	srvStart := seconds / (24 * votingSeconds) * (24 * votingSeconds)
	tpStart := period*length*60 + cns.CalcRotationTimeOffset()
	return sharedRandom(cns, period, length, tpStart >= srvStart)
}

func sharedRandom(cns *common.Consensus, period, length uint64, current bool) [32]byte {
	srv, present := cns.SharedCurrentValue, cns.HasSharedCurrentValue
	if !current {
		srv, present = cns.SharedPreviousValue, cns.HasSharedPreviousValue
	}
	if !present {
		// The specified disaster value is deterministic, not random fallback data.
		input := binary.BigEndian.AppendUint64([]byte("shared-random-disaster"), length)
		input = binary.BigEndian.AppendUint64(input, period)
		return sha3.Sum256(input)
	}
	return srv
}

func responsibleHSDirs(cns *common.Consensus, bpk *crypto.BlindedPublicKey, period, length uint64) ([]common.RouterStatus, error) {
	groups, err := hsdirReplicas(cns, bpk, period, length, clientSRV(cns, period, length), false)
	if err != nil {
		return nil, err
	}
	var out []common.RouterStatus
	for _, group := range groups {
		out = append(out, group...)
	}
	return out, nil
}

func hsdirReplicas(cns *common.Consensus, bpk *crypto.BlindedPublicKey, period, length uint64, srv [32]byte, store bool) ([][]common.RouterStatus, error) {
	spread := cns.Parameter("hsdir_spread_fetch", 3, 1, 128)
	if store {
		spread = cns.Parameter("hsdir_spread_store", 4, 1, 128)
	}
	seen := make(map[[20]byte]bool)
	var out [][]common.RouterStatus
	for replica := 1; replica <= cns.Parameter("hsdir_n_replicas", 2, 1, 16); replica++ {
		ring, err := hsdirRing(srv[:], period, length, cns.RelayInformation, bpk.ServiceIndex(uint64(replica)))
		if err != nil {
			return nil, err
		}
		var group []common.RouterStatus
		for _, r := range ring {
			if seen[r.NodeID] {
				continue
			}
			seen[r.NodeID] = true
			group = append(group, *r)
			if len(group) == spread {
				break
			}
		}
		if len(group) != 0 {
			out = append(out, group)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hs: no responsible HSDirs")
	}
	return out, nil
}

// recvRendezvous2 blocks for RENDEZVOUS2 on the RP circuit and returns its
// handshake info (the service's RENDEZVOUS1 payload relayed by the RP).
func recvRendezvous2(ctx context.Context, circ capi.Circ) ([]byte, error) {
	cell, err := circ.RecvHSControl(ctx)
	if err != nil {
		return nil, fmt.Errorf("hs: wait RENDEZVOUS2: %w", err)
	}
	r2, ok := cell.(*relay.Rendezvous2Cell)
	if !ok {
		return nil, fmt.Errorf("hs: expected RENDEZVOUS2, got %T", cell)
	}
	return r2.HandshakeInfo, nil
}

// serviceStreamTarget returns the BEGIN target for opening the final stream to
// the service on the rendezvous circuit. Per rend-spec-v3 §Managing-streams the
// client sends an empty target address and only the port (e.g. ":80");
// the service maps the port to its local endpoint without a hostname resolve.
func serviceStreamTarget(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ":80"
	}
	return ":" + port
}

// relayStatusFromSpecs reconstructs the minimal RouterStatus needed to extend a
// circuit to the intro point from its link specifiers (ipv4 + ed25519 id).
func relayStatusFromSpecs(specs []lspec.Lspec) *common.RouterStatus {
	rs := &common.RouterStatus{}
	found := false
	for _, s := range specs {
		if _, err := s.Bytes(); err != nil {
			return nil
		}
		switch s.Type() {
		case lspec.LSTYPE_IPV4:
			ipv4, port := decodeIPv4(s)
			if port == 0 {
				return nil
			}
			if found {
				continue
			}
			rs.Ipv4Addr = ipv4
			rs.ORPort = port
			found = true
		case lspec.LSTYPE_ED25519_ID:
			if rs.IdEd25519 != nil {
				return nil
			}
			b, _ := s.Bytes()
			rs.IdEd25519 = b
		case lspec.LSTYPE_LEGACY_ID:
			if rs.NodeID != [20]byte{} {
				return nil
			}
			b, _ := s.Bytes()
			copy(rs.NodeID[:], b)
		}
	}
	if !found || rs.ORPort == 0 || rs.NodeID == [20]byte{} || len(rs.IdEd25519) != 32 {
		return nil
	}
	var err error
	rs.IPLevel, err = common.IPLevel(rs.Ipv4Addr, 0)
	if err != nil {
		return nil
	}
	return rs
}

func decodeIPv4(s lspec.Lspec) (string, uint16) {
	raw, err := s.Bytes()
	if err != nil || len(raw) < 6 {
		return "", 0
	}
	ip := net.IP(raw[:4]).String()
	port := binary.BigEndian.Uint16(raw[4:6])
	return ip, port
}

// introTarget returns the stream target (ip:port) for reaching the intro point.
func introTarget(ip desc.IntroPoint) string {
	rs := relayStatusFromSpecs(ip.LinkSpecs)
	if rs == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", rs.Ipv4Addr, rs.ORPort)
}

// buildIntroducePlaintext includes the RP's onion key (not the service enc-key)
// and every advertised address, as required by rend-spec-v3 3.3.
func buildIntroducePlaintext(cookie [20]byte, rp *common.RouterStatus) ([]byte, error) {
	if rp == nil || rp.NTorOnionKey == nil || len(rp.NTorOnionKey.Bytes()) != 32 || rp.NodeID == [20]byte{} || len(rp.IdEd25519) != 32 || rp.ORPort == 0 {
		return nil, fmt.Errorf("hs: missing authenticated rendezvous metadata")
	}
	specs, err := relayLinkSpecifiers(rp)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), cookie[:]...)
	out = append(out, 0, 1, 0, 32) // no extensions; ntor type, 32-byte key
	out = append(out, rp.NTorOnionKey.Bytes()...)
	return append(out, specs...), nil
}

func relayLinkSpecifiers(rp *common.RouterStatus) ([]byte, error) {
	if rp == nil || rp.NodeID == [20]byte{} || len(rp.IdEd25519) != 32 || rp.ORPort == 0 {
		return nil, fmt.Errorf("hs: invalid relay identity or address")
	}
	ipv4, err := lspec.NewLespecFromIPText(net.JoinHostPort(rp.Ipv4Addr, strconv.Itoa(int(rp.ORPort))))
	if err != nil {
		return nil, err
	}
	specs := []lspec.Lspec{ipv4, lspec.NewNodeID(rp.NodeID), lspec.NewEd25519ID(rp.IdEd25519)}
	if rp.Ipv6Addr != "" {
		ipv6, err := lspec.NewLespecFromIPText(rp.Ipv6Addr)
		if err != nil {
			return nil, err
		}
		specs = append(specs, ipv6)
	}
	var out bytes.Buffer

	out.WriteByte(byte(len(specs)))
	for _, spec := range specs {
		if err := spec.Write(&out); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func ed25519PublicKey(raw []byte) ed25519.PublicKey {
	return ed25519.PublicKey(raw)
}
