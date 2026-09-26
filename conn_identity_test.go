package gonion

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/robogg133/gonion/pkg/common"
)

func TestRelayIdentityPin(t *testing.T) {
	// RSA/Ed25519 relay identities from the Tor/Chutney introduction capture
	// in rend-spec-v3 Appendix G.1. These test matching after CERTS verification,
	// not a substitute for certificate verification or a live handshake.
	rsaID, _ := hex.DecodeString("F823C4F8CC085C792E0AEE0283FE00AD7520B37D")
	edID, _ := hex.DecodeString("728D5DF39B7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF87")
	c := &Conn{relayRSA: [20]byte(rsaID), relayEd: [32]byte(edID)}
	if err := c.CheckRelayFingerprint([20]byte(rsaID)); err != nil {
		t.Fatal(err)
	}
	for _, id := range [][20]byte{{}, {1}} {
		if err := c.CheckRelayFingerprint(id); err == nil {
			t.Fatal("missing or mismatched pin accepted")
		}
	}
	r := &common.RouterStatus{NodeID: [20]byte(rsaID), IdEd25519: bytes.Clone(edID)}
	if err := c.CheckRelayIdentity(r); err != nil {
		t.Fatal(err)
	}
	r.IdEd25519[0] ^= 1
	if err := c.CheckRelayIdentity(r); err == nil {
		t.Fatal("mismatched Ed25519 identity accepted")
	}
}
