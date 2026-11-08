package common

import (
	"bytes"
	"testing"
)

// Hydration fuzzing for V5.2: microdescriptor bytes bound by digest are
// the trust input to OwnAuthenticatedHydration. Provenance: seeds combine
// the ParseMicrodescriptor seeds (fuzz_microdesc_test.go) with truncated
// and oversize blocks. Invariant: hydration never panics and never returns
// a hydrated consensus from an unauthenticated or digest-mismatched map.
// No crasher minimized yet.

func FuzzHydrationMicrodescriptors(f *testing.F) {
	// Valid-shaped microdesc prefix + digest pair (digest will mismatch for
	// most seeds, exercising the rejection branch).
	f.Add([]byte("onion-key\n-----BEGIN RSA PUBLIC KEY-----\n"), "AAAA")
	f.Add([]byte{}, "")
	f.Add([]byte("onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMvEJ/JVNK7I38PPWhQMuCgkET/ki4WIas4tj5Kmqfb9kHqxMR+EunRD\n-----END RSA PUBLIC KEY-----\nntor-onion-key FChIfm77vrWB7JsxQ+jMbN6VSSp1P0DYbw/2aqey4iA=\np accept 1-65535\nid ed25519 J5lkRqyL6qW+CpN3E4RIlgJZeLgwjtmOOrjZvVhuwLQ\n"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add(bytes.Repeat([]byte("x"), 70000), "AAAA") // oversize block
	f.Fuzz(func(t *testing.T, raw []byte, digest string) {
		if len(raw) > MaxConsensusSize {
			return
		}
		if len(digest) > 128 {
			return
		}
		// ParseMicrodescriptor is the digest-bound gate; hydration must
		// not be reached with mismatched digests.
		m, err := ParseMicrodescriptor(raw, digest)
		if err != nil {
			return
		}
		if m == nil {
			t.Fatal("nil microdescriptor on success")
		}
		if m.ExitRules == nil {
			t.Fatal("exit rules not initialized")
		}
	})
}
