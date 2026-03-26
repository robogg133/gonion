package gonion

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"git.servidordomal.fun/robogg133/gonion/internal/common"
)

const (
	HTTP_PATH_CONSENSUS_MICRODESC        string = "/tor/status-vote/current/consensus-microdesc"
	HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT string = "/tor/micro/d/%s"
)

func (c *Circuit) GetConsensus() (*common.Consensus, error) {
	s, err := c.NewStream("dir")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", HTTP_PATH_CONSENSUS_MICRODESC, nil)
	if err != nil {
		return nil, err
	}
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

	if len(src) > 91 {
		return nil, fmt.Errorf("max digests overflow (91): %d", len(src))
	}

	var builder strings.Builder

	digests := make([][]byte, len(src))

	for i, str := range src {
		if _, err := builder.WriteString(str + "-"); err != nil {
			return nil, err
		}

		b, err := base64.RawStdEncoding.DecodeString(str)
		if err != nil {
			return nil, err
		}
		digests[i] = b
	}
	allDigests := strings.TrimSuffix(builder.String(), "-")

	s, err := c.NewStream("dir")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", fmt.Sprintf(HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT, allDigests), nil)
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

	return common.ParseMicrodescFile(bufio.NewReader(microDescs.Body), digests)
}
