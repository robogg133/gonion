package gonion

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

const (
	HTTP_PATH_CONSENSUS_MICRODESC        string = "/tor/status-vote/current/consensus-microdesc"
	HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT string = "/tor/micro/d/%s"
)

const (
	TIMEOUT_DOWNLOADS time.Duration = 10 * time.Minute
)

func (c *Circuit) GetConsensus() (*common.Consensus, error) {
	log := logger(c.Ctx).With().Str("job", "get_consensus").Logger()
	log.Info().Msg("fetching consensus")

	s, err := c.NewStream("dir", 0)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "open directory stream failed", err)
	}

	ctx, cancel := context.WithTimeout(s.Ctx, TIMEOUT_DOWNLOADS)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", HTTP_PATH_CONSENSUS_MICRODESC, nil)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "build consensus request failed", err)
	}

	go func() {
		<-s.Ctx.Done()
		s.Free()
	}()

	if err := req.Write(s); err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "write consensus request failed", err)
	}

	consensusResp, err := http.ReadResponse(bufio.NewReader(s.Reader), req)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "read consensus response failed", err)
	}
	defer consensusResp.Body.Close()

	if consensusResp.StatusCode != http.StatusOK {
		log.Error().Int("status", consensusResp.StatusCode).Msg("consensus HTTP error")
		return nil, Publicf(ErrDirectory, "consensus HTTP status %d", consensusResp.StatusCode)
	}

	consensus, err := common.ParseConsensus(bufio.NewScanner(consensusResp.Body))
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "parse consensus failed", err)
	}

	log.Info().Int("relays", len(consensus.RelayInformation)).Msg("consensus parsed")
	return consensus, nil
}

// GetMicrodescriptors fetches microdescriptors for the given digests.
func (c *Circuit) GetMicrodescriptors(src []string) ([]*common.Microdesc, error) {
	log := logger(c.Ctx).With().Str("job", "get_microdescriptors").Int("count", len(src)).Logger()
	log.Debug().Msg("fetching microdescriptors")

	allDigests, err := buildURL(src)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "build microdesc URL failed", err)
	}

	s, err := c.NewStream("dir", 0)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "open directory stream failed", err)
	}

	ctx, cancel := context.WithTimeout(c.Ctx, TIMEOUT_DOWNLOADS)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT, allDigests), nil)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "build microdesc request failed", err)
	}

	go func() {
		<-ctx.Done()
		s.Free()
	}()

	if err := req.Write(s); err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "write microdesc request failed", err)
	}

	microDescs, err := http.ReadResponse(bufio.NewReader(s.Reader), req)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "read microdesc response failed", err)
	}
	defer microDescs.Body.Close()

	if microDescs.StatusCode != http.StatusOK {
		log.Error().Int("status", microDescs.StatusCode).Msg("microdesc HTTP error")
		return nil, Publicf(ErrDirectory, "microdescriptor HTTP status %d", microDescs.StatusCode)
	}

	out, err := common.ParseMicrodescFile(bufio.NewScanner(microDescs.Body), src)
	if err != nil {
		return nil, fail(c.Ctx, ErrDirectory, "parse microdescriptors failed", err)
	}
	log.Debug().Int("parsed", len(out)).Msg("microdescriptors parsed")
	return out, nil
}

func buildURL(digests []string) (string, error) {
	var builder strings.Builder
	for _, str := range digests {
		if _, err := builder.WriteString(str + "-"); err != nil {
			return "", err
		}
	}
	return strings.TrimSuffix(builder.String(), "-"), nil
}
