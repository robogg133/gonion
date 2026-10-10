package common

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
	"time"

	torcrypto "github.com/robogg133/gonion/pkg/crypto"
	hscrypto "github.com/robogg133/gonion/pkg/hs/crypto"
)

const MaxBridgeDescriptorSize = 20000 // dir-spec 2.1

// BridgeDescriptor is authenticated against a caller-selected RSA identity,
// not the public consensus. Do not insert it into a consensus or mutate it.
type BridgeDescriptor struct {
	Relay     RouterStatus
	Published time.Time
	Expires   time.Time
}

type bridgeItem struct {
	args        []string
	object      []byte
	armor       string
	offset, end int
}

// ParseBridgeDescriptor authenticates a modern bridge's own server descriptor
// (dir-spec 2.1.1, 5.2 and appendix C; cert-spec 2.1). It never enables exit use.
func ParseBridgeDescriptor(data []byte, identity [20]byte, now time.Time) (*BridgeDescriptor, error) {
	if identity == [20]byte{} || len(data) > MaxBridgeDescriptorSize || !bytes.HasPrefix(data, []byte("router ")) || bytes.ContainsAny(data, "\x00\r") {
		return nil, fmt.Errorf("bridge descriptor: invalid identity, size or framing")
	}
	items, err := bridgeItems(data)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"router", "identity-ed25519", "master-key-ed25519", "published", "bandwidth", "proto", "signing-key", "ntor-onion-key", "ntor-onion-key-crosscert", "router-sig-ed25519", "router-signature"} {
		if len(items[name]) != 1 {
			return nil, fmt.Errorf("bridge descriptor: missing or duplicate %s", name)
		}
	}
	for _, name := range []string{"onion-key", "onion-key-crosscert", "fingerprint", "family", "hibernating", "tunnelled-dir-server"} {
		if len(items[name]) > 1 {
			return nil, fmt.Errorf("bridge descriptor: duplicate %s", name)
		}
	}
	// Family certificates need their own specification and validation before
	// they can safely contribute to path diversity. Never silently drop them.
	if len(items["family-cert"]) != 0 {
		return nil, fmt.Errorf("bridge descriptor: family certificates are not supported")
	}
	get := func(name string) bridgeItem { return items[name][0] }
	arg := func(name string, n int) ([]string, error) {
		f := get(name).args
		if len(f) < n {
			return nil, fmt.Errorf("bridge descriptor: too few %s arguments", name)
		}
		return f, nil
	}
	router, err := arg("router", 5)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(router[1])
	if err != nil || !ip.Is4() || !relayNickname(router[0]) {
		return nil, fmt.Errorf("bridge descriptor: invalid router nickname or address")
	}
	d := &BridgeDescriptor{Relay: RouterStatus{Nickname: router[0], NodeID: identity, Ipv4Addr: ip.String()}}
	for i := 2; i < 5; i++ {
		n, err := strconv.ParseUint(router[i], 10, 16)
		if err != nil || i == 2 && n == 0 || i == 3 && n != 0 {
			return nil, fmt.Errorf("bridge descriptor: invalid router port")
		}
		if i == 2 {
			d.Relay.ORPort = uint16(n)
		}
		if i == 4 {
			d.Relay.DirPort = uint16(n)
		}
	}
	published, err := arg("published", 2)
	if err != nil {
		return nil, err
	}
	d.Published, err = time.Parse("2006-01-02 15:04:05", strings.Join(published[:2], " "))
	if err != nil || d.Published.After(now.Add(12*time.Hour)) {
		return nil, fmt.Errorf("bridge descriptor: invalid publication time")
	}
	d.Expires = d.Published.Add(48 * time.Hour) // dir-spec 5.2, ROUTER_MAX_AGE
	bw, err := arg("bandwidth", 3)
	if err != nil {
		return nil, err
	}
	for _, value := range bw[:3] {
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			return nil, fmt.Errorf("bridge descriptor: invalid bandwidth")
		}
	}
	proto, err := arg("proto", 1)
	if err != nil {
		return nil, err
	}
	if err := parseRouterItem("", &d.Relay, append([]string{"pr"}, proto...)); err != nil {
		return nil, err
	}
	if !d.Relay.ProtoVersions.Relay.CheckIsTrue(VERSION_2) {
		return nil, fmt.Errorf("bridge descriptor: ntor/EXTEND2 support is required")
	}
	if h := items["hibernating"]; len(h) != 0 && (len(h[0].args) == 0 || h[0].args[0] != "0") {
		return nil, fmt.Errorf("bridge descriptor: hibernating or invalid hibernation state")
	}
	if len(items["accept"])+len(items["reject"]) == 0 {
		return nil, fmt.Errorf("bridge descriptor: missing exit policy")
	}
	for _, a := range items["or-address"] {
		if err := parseRouterItem("", &d.Relay, append([]string{"a"}, a.args...)); err != nil {
			return nil, err
		}
	}
	if f := items["family"]; len(f) != 0 {
		d.Relay.Family, err = ParseRelayFamily(strings.Join(f[0].args, " "))
		if err != nil {
			return nil, err
		}
	}
	keyItem := get("signing-key")
	key, err := bridgeRSAKey(keyItem)
	if err != nil {
		return nil, err
	}
	if sha1.Sum(keyItem.object) != identity {
		return nil, fmt.Errorf("bridge descriptor: RSA identity mismatch")
	}
	if f := items["fingerprint"]; len(f) != 0 {
		pin, err := directoryDigest(strings.Join(f[0].args, ""))
		if err != nil || pin != identity {
			return nil, fmt.Errorf("bridge descriptor: fingerprint mismatch")
		}
	}
	master, err := arg("master-key-ed25519", 1)
	if err != nil {
		return nil, err
	}
	d.Relay.IdEd25519, err = bridgeBase64(master[0])
	if err != nil {
		return nil, err
	}
	if err := hscrypto.ValidateEd25519PublicKey(d.Relay.IdEd25519); err != nil {
		return nil, err
	}
	idItem := get("identity-ed25519")
	if len(bytes.Trim(data[get("router").end:idItem.offset], "\n")) != 0 || len(idItem.args) != 0 {
		return nil, fmt.Errorf("bridge descriptor: misplaced identity certificate")
	}
	idCert, err := bridgeCertificate(idItem, 4, d.Relay.IdEd25519, now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(idCert.Extensions[4].Data, d.Relay.IdEd25519) {
		return nil, fmt.Errorf("bridge descriptor: missing identity signing-key extension")
	}
	if err := hscrypto.ValidateEd25519PublicKey(idCert.CertifiedKey); err != nil {
		return nil, err
	}
	ntor, err := arg("ntor-onion-key", 1)
	if err != nil {
		return nil, err
	}
	ntorKey, err := bridgeBase64(ntor[0])
	if err != nil {
		return nil, err
	}
	ccItem := get("ntor-onion-key-crosscert")
	if len(ccItem.args) != 1 || (ccItem.args[0] != "0" && ccItem.args[0] != "1") {
		return nil, fmt.Errorf("bridge descriptor: invalid ntor sign bit")
	}
	ccKey, err := hscrypto.Ed25519FromX25519(ntorKey, ccItem.args[0][0]-'0')
	if err != nil {
		return nil, err
	}
	cc, err := bridgeCertificate(ccItem, 10, ccKey, now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cc.CertifiedKey, d.Relay.IdEd25519) {
		return nil, fmt.Errorf("bridge descriptor: ntor cross-certificate identity mismatch")
	}
	d.Relay.NTorOnionKey, err = ecdh.X25519().NewPublicKey(ntorKey)
	if err != nil {
		return nil, err
	}
	for _, cert := range []*torcrypto.TorCert{idCert, cc} {
		expires := time.Unix(int64(cert.ExpirationDate)*3600, 0)
		if expires.Before(d.Expires) {
			d.Expires = expires
		}
	}
	if !now.Before(d.Expires) {
		return nil, fmt.Errorf("bridge descriptor: expired")
	}
	// Current C Tor permits omission of TAP keys, but not a partial pair.
	if len(items["onion-key"]) != len(items["onion-key-crosscert"]) {
		return nil, fmt.Errorf("bridge descriptor: incomplete TAP cross-certificate")
	}
	if len(items["onion-key"]) != 0 {
		tap, err := bridgeRSAKey(get("onion-key"))
		if err != nil {
			return nil, err
		}
		tapCC := get("onion-key-crosscert")
		if len(tapCC.args) != 0 || tapCC.armor != "CROSSCERT" || !bridgeRSAPrefix(tap, tapCC.object, append(identity[:], d.Relay.IdEd25519...)) {
			return nil, fmt.Errorf("bridge descriptor: invalid TAP cross-certificate")
		}
	}
	edSig, rsaSig := get("router-sig-ed25519"), get("router-signature")
	if len(edSig.args) != 1 || len(rsaSig.args) != 0 || edSig.end != rsaSig.offset || rsaSig.armor != "SIGNATURE" || len(bytes.Trim(data[rsaSig.end:], "\n")) != 0 {
		return nil, fmt.Errorf("bridge descriptor: invalid signature placement")
	}
	sig, err := bridgeBase64(edSig.args[0])
	if err != nil {
		return nil, err
	}
	end := edSig.offset + len("router-sig-ed25519 ")
	if !bytes.HasPrefix(data[edSig.offset:], []byte("router-sig-ed25519 ")) {
		return nil, fmt.Errorf("bridge descriptor: invalid Ed25519 signature line")
	}
	h := sha256.New()
	h.Write([]byte("Tor router descriptor signature v1"))
	h.Write(data[:end])
	if !ed25519.Verify(idCert.CertifiedKey, h.Sum(nil), sig) {
		return nil, fmt.Errorf("bridge descriptor: invalid Ed25519 signature")
	}
	digest := sha1.Sum(data[:rsaSig.offset+len("router-signature\n")])
	if !bytes.HasPrefix(data[rsaSig.offset:], []byte("router-signature\n")) || rsa.VerifyPKCS1v15(key, 0, digest[:], rsaSig.object) != nil {
		return nil, fmt.Errorf("bridge descriptor: invalid RSA signature")
	}
	return d, nil
}

func bridgeItems(data []byte) (map[string][]bridgeItem, error) {
	out := make(map[string][]bridgeItem)
	for offset := 0; offset < len(data); {
		end := bytes.IndexByte(data[offset:], '\n')
		if end < 0 {
			return nil, fmt.Errorf("bridge descriptor: truncated line")
		}
		end += offset + 1
		f := strings.Fields(string(data[offset : end-1]))
		if len(f) == 0 {
			offset = end
			continue
		}
		item := bridgeItem{args: f[1:], offset: offset, end: end}
		if bytes.HasPrefix(data[end:], []byte("-----BEGIN ")) {
			lineEnd := bytes.IndexByte(data[end:], '\n')
			if lineEnd < 0 {
				return nil, fmt.Errorf("bridge descriptor: truncated object")
			}
			line := string(data[end : end+lineEnd])
			if !strings.HasSuffix(line, "-----") {
				return nil, fmt.Errorf("bridge descriptor: malformed object")
			}
			item.armor = strings.TrimSuffix(strings.TrimPrefix(line, "-----BEGIN "), "-----")
			start := end + lineEnd + 1
			marker := []byte("-----END " + item.armor + "-----\n")
			n := bytes.Index(data[start:], marker)
			if n < 0 {
				return nil, fmt.Errorf("bridge descriptor: unterminated object")
			}
			var err error
			item.object, err = bridgeBase64(string(bytes.ReplaceAll(data[start:start+n], []byte("\n"), nil)))
			if err != nil {
				return nil, err
			}
			item.end = start + n + len(marker)
		}
		out[f[0]] = append(out[f[0]], item)
		offset = item.end
	}
	return out, nil
}

func bridgeBase64(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return base64.StdEncoding.Strict().DecodeString(s)
	}
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

func bridgeRSAKey(item bridgeItem) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKCS1PublicKey(item.object)
	if err != nil || item.armor != "RSA PUBLIC KEY" || len(item.args) != 0 || key.N.BitLen() != 1024 || key.E < 3 || key.E%2 == 0 {
		return nil, fmt.Errorf("bridge descriptor: invalid RSA key")
	}
	return key, nil
}

func bridgeCertificate(item bridgeItem, kind byte, key []byte, now time.Time) (*torcrypto.TorCert, error) {
	cert, err := torcrypto.ParseIdentityVSigningCert(item.object)
	if err != nil {
		return nil, err
	}
	if item.armor != "ED25519 CERT" || cert.CertType != kind || cert.CertKeyType != 1 {
		return nil, fmt.Errorf("bridge descriptor: invalid certificate purpose")
	}
	if err := cert.Verify(key, now); err != nil {
		return nil, err
	}
	return cert, nil
}

// TAP cross-certificates sign a prefix, not a fixed-length digest. Validate the
// full PKCS#1 v1.5 padding while permitting trailing signed data (dir-spec 2.1.1).
func bridgeRSAPrefix(key *rsa.PublicKey, sig, prefix []byte) bool {
	s := new(big.Int).SetBytes(sig)
	if len(sig) != key.Size() || s.Cmp(key.N) >= 0 {
		return false
	}
	b := new(big.Int).Exp(s, big.NewInt(int64(key.E)), key.N).FillBytes(make([]byte, key.Size()))
	if b[0] != 0 || b[1] != 1 {
		return false
	}
	i := 2
	for i < len(b) && b[i] == 255 {
		i++
	}
	return i >= 10 && i < len(b) && b[i] == 0 && bytes.HasPrefix(b[i+1:], prefix)
}

func relayNickname(s string) bool {
	return len(s) > 0 && len(s) <= 19 && strings.IndexFunc(s, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') }) < 0
}
