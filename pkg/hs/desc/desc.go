// Package desc fetches, decrypts and parses tor hidden-service v3 descriptors
// on the client side (rend-spec-v3 §HSDESC / §DESC-FETCH / §DESC-ENCRYPT).
package desc

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
	"github.com/robogg133/gonion/pkg/hs/crypto"
	"github.com/robogg133/gonion/pkg/lspec"
)

// IntroPoint is a single introduction point extracted from a decrypted
// descriptor (rend-spec-v3 §2.5). The client uses it to build the
// ESTABLISH_INTRO circuit and to send INTRODUCE1.
type IntroPoint struct {
	// OnionKey is the intro point encryption public key (KP_hs_ipt_sid), "B".
	OnionKey []byte
	// AuthKey is the intro auth public key (KP_hs_ipt_sid auth).
	AuthKey []byte
	// LinkSpecs are the link specifiers needed to reach the intro point
	// (ipv4 / legacy id / ed25519 id).
	LinkSpecs []lspec.Lspec
}

// Descriptor is the parsed, decrypted hidden-service descriptor. Only the
// fields the client needs for the rendezvous are surfaced.
type Descriptor struct {
	// Version is the descriptor format version (3).
	Version int
	// LifetimeSeconds is the descriptor lifetime in seconds.
	LifetimeSeconds int
	// Subcredential is the derived subcredential used in the intro/rendezvous
	// crypto (rend-spec-v3 §KEYBLIND).
	Subcredential []byte
	// IntroPoints lists the introduction points.
	IntroPoints []IntroPoint
	// SuperencryptedRaw keeps the decrypted outer plaintext. The inner
	// superencrypted layer parsing (multiple replicas, intro auth) is covered
	// progressively; the happy path decodes intro points from this layer.
	SuperencryptedRaw []byte
}

// Fetch opens an HTTP stream to the given HSDir and retrieves the encrypted
// descriptor for the blinded key. The URL is
// /tor/hs/3/<descriptor-id-hex> (rend-spec-v3 §DESC-FETCH / §HSADDRESS).
//
// circ is the circuit used to reach the HSDir (already extended to it), and
// the descriptor id <z> is derived from the blinded key via crypto.DescriptorID.
func Fetch(ctx context.Context, circ capi.Circ, hsdir common.RouterStatus, blindedPk *crypto.BlindedPublicKey, periodNum, periodLen, replica uint64) (*Descriptor, error) {
	log := zerolog.Ctx(ctx)

	id := crypto.DescriptorID(blindedPk, periodNum, periodLen, replica)
	urlPath := fmt.Sprintf("/tor/hs/3/%s", hex.EncodeToString(id[:]))

	stream, err := circ.NewStream(fmt.Sprintf("%s:%d", hsdir.Ipv4Addr, hsdir.ORPort), circ.HopCount()-1)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: open hsdir stream: %w", err)
	}
	defer stream.Free()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: build request: %w", err)
	}
	if err := req.Write(stream.Conn()); err != nil {
		return nil, fmt.Errorf("hs/desc: write request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream.Conn()), req)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: read response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hs/desc: hsdir returned %d", resp.StatusCode)
	}

	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: read body: %w", err)
	}

	keys, err := crypto.DescKeys(blindedPk)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: derive keys: %w", err)
	}

	plain, err := crypto.DecryptDescriptor(keys, blob)
	if err != nil {
		return nil, fmt.Errorf("hs/desc: decrypt: %w", err)
	}

	desc, err := Parse(plain)
	if err != nil {
		return nil, err
	}

	log.Debug().
		Int("intro_points", len(desc.IntroPoints)).
		Int("version", desc.Version).
		Msg("hs descriptor fetched and parsed")

	subcred, err := deriveSubcredential(blindedPk)
	if err != nil {
		return nil, err
	}
	desc.Subcredential = subcred[:]
	return desc, nil
}

// deriveSubcredential computes the v3 subcredential (rend-spec-v3 §KEYBLIND):
//
//	credential   = H("credential" || service-pubkey)
//	subcredential = H("subcredential" || credential || blindPk)
func deriveSubcredential(blindedPk *crypto.BlindedPublicKey) (crypto.SubCredential, error) {
	cred, err := crypto.GenerateCredential(blindedPk.Pk())
	if err != nil {
		return nil, fmt.Errorf("hs/desc: generate credential: %w", err)
	}
	sub, err := crypto.GenerateSubCredential(cred, blindedPk.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hs/desc: generate subcredential: %w", err)
	}
	return sub, nil
}

// Parse decodes the plaintext (outer decrypted layer) of a v3 descriptor and
// extracts the introduction points (rend-spec-v3 §2.5 "introduction-points").
//
// The descriptor is a sequence of "key: value" lines; the part we need is:
//
//	"introduction-points" SP "auth-key" SP "<base64>" NL
//	<base64-encoded INTRODUCE1-style block: onion-key / auth-key / link-specifiers>
//
// A complete superencrypted parse (multiple replicas, intro auth) is covered
// progressively; here we surface the intro points required for the rendezvous.
func Parse(body []byte) (*Descriptor, error) {
	desc := &Descriptor{}

	var inIntroPoints bool
	var introLines []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := sc.Text()
		if inIntroPoints {
			// The block ends at an empty line (the next section).
			if strings.TrimSpace(line) == "" {
				inIntroPoints = false
				continue
			}
			introLines = append(introLines, line)
			continue
		}
		switch {
		case strings.HasPrefix(line, "version "):
			if _, err := fmt.Sscanf(line, "version %d", &desc.Version); err != nil {
				return nil, fmt.Errorf("hs/desc: parse version: %w", err)
			}
		case strings.HasPrefix(line, "lifetime "):
			if _, err := fmt.Sscanf(line, "lifetime %d", &desc.LifetimeSeconds); err != nil {
				return nil, fmt.Errorf("hs/desc: parse lifetime: %w", err)
			}
		case strings.HasPrefix(line, "introduction-points"):
			inIntroPoints = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hs/desc: scan: %w", err)
	}
	desc.SuperencryptedRaw = body

	if len(introLines) == 0 {
		// No intro points in the outer layer (likely superencrypted inner
		// layer). Return what we have; the orchestrator handles the fallback.
		return desc, nil
	}

	ips, err := parseIntroPoints(introLines)
	if err != nil {
		return nil, err
	}
	desc.IntroPoints = ips
	return desc, nil
}

// parseIntroPoints decodes the base64 INTRODUCE1-style intro block for each
// "introduction-points" entry. rend-spec-v3 §FMT_INTRO1:
//
//	ONION_KEY_TYPE(1) ONION_KEY_LEN(2) ONION_KEY | AUTH_KEY_TYPE(1)
//	AUTH_KEY_LEN(2) AUTH_KEY | N_EXTENSIONS(1) exts | LINK_SPECIFIERS
func parseIntroPoints(lines []string) ([]IntroPoint, error) {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(strings.TrimSpace(l))
	}
	raw, err := base64Decode(b.String())
	if err != nil {
		return nil, fmt.Errorf("hs/desc: decode intro points: %w", err)
	}
	return decodeIntroBlock(raw)
}

// decodeIntroBlock parses the binary intro point listing.
func decodeIntroBlock(raw []byte) ([]IntroPoint, error) {
	var ips []IntroPoint
	r := newBufReader(raw)
	for {
		if _, err := r.PeekByte(); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		// PeekByte does not advance; fall through and read normally.

		// onion key: type(1) len(2) key; auth key: type(1) len(2) key
		onionKey, err := readKeyField(r)
		if err != nil {
			return nil, fmt.Errorf("hs/desc: intro onion key: %w", err)
		}
		authKey, err := readKeyField(r)
		if err != nil {
			return nil, fmt.Errorf("hs/desc: intro auth key: %w", err)
		}
		// extensions: N_EXTENSIONS(1) then exts; skip (legacy empty).
		nExt, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("hs/desc: intro exts count: %w", err)
		}
		for range nExt {
			if err := skipExt(r); err != nil {
				return nil, err
			}
		}
		specs, err := readLinkSpecifiers(r)
		if err != nil {
			return nil, fmt.Errorf("hs/desc: intro link specifiers: %w", err)
		}
		ips = append(ips, IntroPoint{
			OnionKey:  onionKey,
			AuthKey:   authKey,
			LinkSpecs: specs,
		})
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("hs/desc: no intro points decoded")
	}
	return ips, nil
}
