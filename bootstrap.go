package gonion

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/robogg133/gonion/shared"
)

const (
	GET_CONSENSUS_MICRODESC_PAYLOAD string = "GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\n\r\n"
)

const (
	GET_MICRODESC_PAYLOAD_BASE  string = "GET /tor/micro/d/%s "
	GET_MICRODESC_PAYLOAD_FINAL string = "HTTP/1.0\r\n\r\n"
)

// Bootstrap will open conections to relays and
func Bootstrap() error {

	if err := getConsensus(c); err != nil {
		return err
	}

	clone := *shared.GetGlobalConsensus()

	totalRelays := len(clone.RelayInformation)
	ammount := uint(float32(totalRelays) * 0.6)
	for i := range ammount {
		fmt.Println(i)
	}

	return nil
}

func encodeMicrodescHTTPPayload(microdescDigest ...string) string {

	if len(microdescDigest) > 92 {
		panic("too much node id's")
	}

	var builder strings.Builder

	for _, s := range microdescDigest {
		if _, err := builder.WriteString(s); err != nil {
			panic(err)
		}
		if _, err := builder.WriteRune('-'); err != nil {
			panic(err)
		}
	}

	final := fmt.Sprintf(GET_MICRODESC_PAYLOAD_BASE, strings.TrimSuffix(builder.String(), "-"))
	final = final + GET_MICRODESC_PAYLOAD_FINAL

	return final
}

func getConsensus(c *Circuit) error {

	s, err := c.NewStream("dir")
	if err != nil {
		return err
	}

	// Writing get consensus microdesc flavor
	req, err := http.NewRequest("GET", GET_CONSENSUS_MICRODESC_PAYLOAD, nil)
	if err != nil {
		return err
	}
	req.Write(s)

	// Reading response
	resp, err := http.ReadResponse(bufio.NewReader(s.Reader), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	defer s.Reader.Close()

	consensus, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	parsedConsensus, err := shared.ParseConsensus(bufio.NewScanner(bytes.NewReader(consensus)))
	if err != nil {
		return err
	}

	shared.SetGlobalConsensus(*parsedConsensus)

	return nil
}

func (c *Conn) getConsensusJob() {

}
