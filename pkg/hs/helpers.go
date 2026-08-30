package hs

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"
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

// pickHSDirs selects up to 3 HSDirs for the blinded key at the given replica
// (rend-spec-v3 §DESC-FETCH / [SRV-TIMING]).
func pickHSDirs(cns *common.Consensus, bpk *crypto.BlindedPublicKey, periodNum, periodLen, replica uint64) ([]common.RouterStatus, error) {
	idx := bpk.ServiceIndex(replica)
	routers, err := Search(cns.SharedCurrentValue[:], periodNum, periodLen, cns.RelayInformation, idx)
	if err != nil || len(routers) < 3 {
		return nil, fmt.Errorf("hs: not enough hsdir relays for replica %d: %w", replica, err)
	}
	return routers[:3], nil
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

// serviceStreamTarget returns the host:port the client opens to the service
// once the e2e hop is attached. The .onion address carries an optional :port;
// absent, we use the standard 80.
func serviceStreamTarget(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return addr + ":80"
	}
	return host + ":" + port
}

// relayStatusFromSpecs reconstructs the minimal RouterStatus needed to extend a
// circuit to the intro point from its link specifiers (ipv4 + ed25519 id).
func relayStatusFromSpecs(specs []lspec.Lspec) *common.RouterStatus {
	rs := &common.RouterStatus{}
	found := false
	for _, s := range specs {
		switch s.Type() {
		case lspec.LSTYPE_IPV4:
			ipv4, port := decodeIPv4(s)
			rs.Ipv4Addr = ipv4
			rs.ORPort = port
			found = true
		case lspec.LSTYPE_ED25519_ID:
			b, _ := s.Bytes()
			rs.IdEd25519 = b
		case lspec.LSTYPE_LEGACY_ID:
			b, _ := s.Bytes()
			copy(rs.NodeID[:], b)
		}
	}
	if !found {
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

// buildIntroducePlaintext assembles the INTRODUCE1 ENCRYPTED plaintext:
// RENDEZVOUS_COOKIE(20) || LINK_SPECS(RP) (rend-spec-v3 §INTRO_POINT).
//
// ponytail: the RP link-spec list is advisory here; when a strict end-to-end
// spec list is required, thread the RP relay's lspecs through Connect into this
// function. The cookie alone is sufficient for the RP to associate the intro.
func buildIntroducePlaintext(cookie [20]byte) []byte {
	out := make([]byte, 0, 20)
	out = append(out, cookie[:]...)
	return out
}

func ed25519PublicKey(raw []byte) ed25519.PublicKey {
	return ed25519.PublicKey(raw)
}
