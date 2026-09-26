package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

func vectorHex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHsNtorOfficialVector uses the Tor/Chutney capture published in
// https://raw.githubusercontent.com/torproject/torspec/main/rend-spec-v3.txt
// Appendix G.1.
// Unlike a local round trip, these expectations do not share our MAC code.
func TestHsNtorOfficialVector(t *testing.T) {
	auth := vectorHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	sub := vectorHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	private := func(text string) *ecdh.PrivateKey {
		t.Helper()
		k, err := ecdh.X25519().NewPrivateKey(vectorHex(t, text))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	b := private("A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	x := private("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	y := private("68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55")
	plain := vectorHex(t, `
		6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCA
		C4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F0000
		0113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B
		7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF870000000000
		0000000000000000000000000000000000000000000000000000000000000000
		000000000000000000000000000000000000000000000000000000000000`)
	wire := vectorHex(t, `
		000000000000000000000000000000000000000002002034E171E4358E501BFF
		21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00BF04348B46D09AED
		726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5DADBECCCB38E37830
		4DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175FA446525C1B9D5530
		563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB187FBB48C63298B0E8
		3F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDAE31EF5F0913B9A9C
		7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3FC37CD95E5B8BFB3E
		35717012B78B4930569F895CB349A07538E42309C993223AEA77EF8AEA64F25D
		DEE97DA623F1AEC0A47F150002150455845C385E5606E41A9A199E7111D54EF2
		D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8`)
	keys, blob, err := HsClientIntro(x, b.PublicKey(), auth, sub, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.ENCKey, vectorHex(t, "9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706")) ||
		!bytes.Equal(keys.MACKey, vectorHex(t, "FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5")) {
		t.Fatal("introduction KDF differs from official vector")
	}
	if !bytes.Equal(blob, wire[56:]) {
		t.Fatalf("INTRODUCE1 differs from official vector: %X", blob)
	}
	X, recovered, err := HsServiceIntro(b, auth, sub, wire[56:])
	if err != nil || !bytes.Equal(recovered, plain) || !X.Equal(x.PublicKey()) {
		t.Fatalf("official INTRODUCE2 rejected or decrypted incorrectly: %v", err)
	}
	reply := vectorHex(t, `8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700
		4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208`)
	gotReply, serviceSeed, err := HsServiceRendezvous(X, b.PublicKey(), auth, b, y)
	if err != nil || !bytes.Equal(gotReply, reply) {
		t.Fatalf("RENDEZVOUS1 differs from official vector: %X, %v", gotReply, err)
	}
	seed, err := HsClientFinishRendezvous(x, b.PublicKey(), auth, reply)
	if err != nil || !bytes.Equal(seed, vectorHex(t, "4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")) {
		t.Fatalf("rendezvous seed differs from official vector: %X, %v", seed, err)
	}

	if !bytes.Equal(serviceSeed, seed) {
		t.Fatal("service and client derived different seeds")
	}
	_, rawPlain, err := HsServiceIntroWithHeader(b, auth, sub, wire[:56], wire[56:])
	if err != nil || !bytes.Equal(rawPlain, plain) {
		t.Fatalf("raw header: %v", err)
	}
	badHeader := bytes.Clone(wire[:56])
	badHeader[55] = 1
	badHeader = append(badHeader, 99, 0)
	if _, _, err := HsServiceIntroWithHeader(b, auth, sub, badHeader, wire[56:]); err == nil {
		t.Fatal("unauthenticated outer extension accepted")
	}

	// Section 4.2.1 gives the expansion formula but no output vector. Use the
	// official seed with a separate SHAKE invocation, not the production KDF.
	want := make([]byte, 128)
	shake := sha3.NewShake256()
	shake.Write(seed)
	shake.Write([]byte("tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"))
	shake.Read(want)
	e2e, err := E2EKeys(seed, sub)
	if err != nil {
		t.Fatal(err)
	}
	got := append(append(append(append([]byte{}, e2e.Df...), e2e.Db...), e2e.Kf...), e2e.Kb...)
	if !bytes.Equal(got, want) {
		t.Fatal("E2E expansion differs from section 4.2.1")
	}

	for _, offset := range []int{0, 32, len(blob) - 1} {
		bad := append([]byte{}, blob...)
		bad[offset] ^= 1
		if _, _, err := HsServiceIntro(b, auth, sub, bad); err == nil {
			t.Fatalf("accepted corrupted introduction at offset %d", offset)
		}
	}
	reply[63] ^= 1
	if _, err := HsClientFinishRendezvous(x, b.PublicKey(), auth, reply); err == nil {
		t.Fatal("accepted corrupted rendezvous AUTH")
	}
}

func TestHsNtorRejectsInvalidInput(t *testing.T) {
	x, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	zero, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{2}, 32)
	if _, _, err := HsClientIntro(x, zero, key, key, nil); err == nil {
		t.Fatal("ignored low-order ECDH error")
	}
	if _, _, err := HsClientIntro(nil, x.PublicKey(), key, key, nil); err == nil {
		t.Fatal("accepted nil private key")
	}
	if _, _, err := HsClientIntro(x, x.PublicKey(), key[:31], key, nil); err == nil {
		t.Fatal("accepted short authentication key")
	}
	if _, _, err := HsClientIntro(x, x.PublicKey(), key, key[:31], nil); err == nil {
		t.Fatal("accepted short subcredential")
	}
	if _, _, err := HsClientIntro(x, x.PublicKey(), key, key, make([]byte, 379)); err == nil {
		t.Fatal("accepted oversized introduction")
	}
	if _, _, err := HsServiceIntro(x, key, key, make([]byte, 443)); err == nil {
		t.Fatal("accepted oversized INTRODUCE2")
	}
	if _, err := HsClientFinishRendezvous(nil, zero, key, make([]byte, 64)); err == nil {
		t.Fatal("accepted nil rendezvous key")
	}
	if _, err := HsServiceRendezvousReply(x.PublicKey(), zero, key, x, x); err == nil {
		t.Fatal("accepted mismatched service public key")
	}
}
