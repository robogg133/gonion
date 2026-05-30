package gonion

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/robogg133/gonion/internal/common"
)

const (
	HTTP_PATH_CONSENSUS_MICRODESC        string = "/tor/status-vote/current/consensus-microdesc"
	HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT string = "/tor/micro/d/%s"
)

const (
	TIMEOUT_DOWNLOADS time.Duration = 10 * time.Minute
)

func (c *Circuit) GetConsensus() (*common.Consensus, error) {
	s, err := c.NewStream("dir")
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_DOWNLOADS)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", HTTP_PATH_CONSENSUS_MICRODESC, nil)
	if err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		s.Free()
	}()

	if err := req.Write(s); err != nil {
		return nil, err
	}

	consensusResp, err := http.ReadResponse(bufio.NewReader(s.Reader), req)
	if err != nil {
		return nil, err
	}

	defer consensusResp.Body.Close()

	consensus, err := common.ParseConsensus(bufio.NewScanner(consensusResp.Body))
	if err != nil {
		return nil, err
	}

	return consensus, nil
}

// GetMicrodescriptors uses src with microdescriptorsDigset and return it's values
func (c *Circuit) GetMicrodescriptors(src []string) ([]*common.Microdesc, error) {

	allDigests, err := buildURL(src)
	if err != nil {
		return nil, err
	}

	s, err := c.NewStream("dir")
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_DOWNLOADS)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT, allDigests), nil)
	if err != nil {
		return nil, err
	}

	if err := req.Write(s); err != nil {
		return nil, err
	}

	microDescs, err := http.ReadResponse(bufio.NewReader(s.Reader), req)
	if err != nil {
		return nil, err
	}

	defer microDescs.Body.Close()

	return common.ParseMicrodescFile(bufio.NewScanner(microDescs.Body), src)
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
