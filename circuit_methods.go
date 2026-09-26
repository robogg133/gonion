package gonion

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers"
	"github.com/robogg133/gonion/pkg/parsers/microdesc"
	"github.com/robogg133/gonion/pkg/parsers/usual"
)

const (
	HTTP_PATH_CONSENSUS                                = "/tor/status-vote/current/consensus"
	HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT               = "/tor/micro/d/%s"
	ConsensusFlavorNS                                  = common.ConsensusFlavorNS
	ConsensusFlavorMicrodesc                           = common.ConsensusFlavorMicrodesc
	TIMEOUT_DOWNLOADS                    time.Duration = 10 * time.Minute
)

func consensusRequestPath(flavor string) (string, string, error) {
	switch flavor {
	case "", ConsensusFlavorNS:
		return HTTP_PATH_CONSENSUS, ConsensusFlavorNS, nil
	case ConsensusFlavorMicrodesc:
		return HTTP_PATH_CONSENSUS + "-microdesc", flavor, nil
	default:
		return "", "", Publicf(ErrDirectory, "unsupported consensus flavor %q", flavor)
	}
}

func (c *Circuit) GetConsensus(flavor string) (*common.Consensus, error) {
	return c.getConsensus(c.Ctx, flavor)
}

func (c *Circuit) getConsensus(ctx context.Context, flavor string) (*common.Consensus, error) {
	path, expected, err := consensusRequestPath(flavor)
	if err != nil {
		return nil, err
	}
	data, err := c.downloadDirectory(ctx, path, common.MaxConsensusSize)
	if err != nil {
		return nil, err
	}
	parsed, err := parseConsensusResponse(data, expected)
	if err != nil {
		return nil, err
	}
	return c.authenticateConsensus(ctx, parsed)
}

func (c *Circuit) authenticateConsensus(ctx context.Context, candidate *common.Consensus) (*common.Consensus, error) {
	if candidate == nil {
		return nil, Public(ErrDirectory, "missing consensus")
	}
	pins := common.DefaultAuthorities()
	if verified, err := common.AuthenticateConsensus(candidate.RawDocument, candidate.AuthorityCertificates, pins, time.Now().UTC()); err == nil {
		return verified, nil
	}
	certs, err := c.downloadDirectory(ctx, "/tor/keys/all", 4<<20)
	if err != nil {
		return nil, err
	}
	return common.AuthenticateConsensus(candidate.RawDocument, certs, pins, time.Now().UTC())
}

func parseConsensusResponse(data []byte, expected string) (*common.Consensus, error) {
	c, err := (usual.Parser{}).Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if c.Flavor != expected {
		return nil, Publicf(ErrDirectory, "consensus flavor mismatch: requested %s, received %s", expected, c.Flavor)
	}
	return c, nil
}

// GetMicrodescriptors returns results in requested digest order. Missing or
// mismatched descriptors remain nil; bootstrap must not publish them as loaded.
func (c *Circuit) GetMicrodescriptors(src []string) ([]*common.Microdesc, error) {
	return c.getMicrodescriptors(c.Ctx, src)
}

func (c *Circuit) getMicrodescriptors(ctx context.Context, src []string) ([]*common.Microdesc, error) {
	if len(src) == 0 {
		return []*common.Microdesc{}, nil
	}
	allDigests, err := buildURL(src)
	if err != nil {
		return nil, err
	}
	data, err := c.downloadDirectory(ctx, fmt.Sprintf(HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT, allDigests), 4<<20)
	if err != nil {
		return nil, err
	}
	return (microdesc.Parser{}).Parse(bytes.NewReader(data), src)
}

func buildURL(digests []string) (string, error) {
	if len(digests) == 0 || len(digests) > 92 {
		return "", Public(ErrDirectory, "microdescriptor request must contain 1 to 92 digests")
	}
	for _, digest := range digests {
		b, err := base64.RawStdEncoding.Strict().DecodeString(digest)
		if err != nil || len(b) != 32 {
			return "", Public(ErrDirectory, "invalid microdescriptor digest")
		}
	}
	return strings.Join(digests, "-"), nil
}

func (c *Circuit) downloadDirectory(parent context.Context, path string, limit int64) ([]byte, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	s, err := c.NewStream("dir", 0)
	if err != nil {
		return nil, fail(parent, ErrDirectory, "open directory stream failed", err)
	}
	defer s.Free()
	ctx, cancel := context.WithTimeout(parent, TIMEOUT_DOWNLOADS)
	defer cancel()
	// Request.Write and ReadResponse use a raw Tor stream, not http.Transport:
	// merely attaching a context to the request does not interrupt their I/O.
	stop := context.AfterFunc(ctx, func() {
		s.ctxCancel(ctx.Err())
		_ = s.Reader.Close()
	})
	defer stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if err := req.Write(s); err != nil {
		return nil, fail(parent, ErrDirectory, "write directory request failed", err)
	}
	data, err := readDirectoryResponse(s.Reader, req, limit)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fail(parent, ErrDirectory, "read directory response failed", err)
	}
	return data, nil
}

func readDirectoryResponse(r io.Reader, req *http.Request, limit int64) ([]byte, error) {
	reader := bufio.NewReader(r)
	var header bytes.Buffer
	for {
		line, err := reader.ReadSlice('\n')
		if header.Len()+len(line) > 64<<10 {
			return nil, fmt.Errorf("directory: HTTP headers too large")
		}
		header.Write(line)
		if err != nil && err != bufio.ErrBufferFull {
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(header.Bytes()), reader)), req)
	if err != nil {
		return nil, err
	}
	// Do not drain an error response or an oversized body on Close. The
	// directory stream is owned by this request and is freed by the caller.
	if resp.StatusCode != http.StatusOK {
		return nil, Publicf(ErrDirectory, "directory HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("directory: response body too large")
	}
	encoded := &io.LimitedReader{R: resp.Body, N: limit + 1}
	var body io.Reader = encoded
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "deflate":
		z, err := zlib.NewReader(encoded)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		body = z
	case "gzip":
		z, err := gzip.NewReader(encoded)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		body = z
	default:
		return nil, fmt.Errorf("directory: unsupported content encoding")
	}
	data, err := parsers.ReadAll(body, limit)
	if err != nil {
		return nil, err
	}
	if encoded.N <= 0 {
		return nil, fmt.Errorf("directory: encoded response too large")
	}
	return data, nil
}
