package gonion_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/robogg133/gonion"
)

func TestNewConn(t *testing.T) {

	relayConn, err := gonion.NewConn("23.141.188.38:443")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Creating circuit")
	circuit, err := relayConn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Circuit created")

	fmt.Println("Creating stream")
	stream, err := circuit.NewStream("dir")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Stream created")

	fmt.Println("Writing Payload")

	req, err := http.NewRequest("GET", "/tor/micro/d/FFLmryM0N2S+0JJ3P+H4YA89iwmLe68tvlkzIGz3G60", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Write(stream)
	fmt.Println("Wrote the payload")

	fmt.Println("Reading from pipe")

	resp, err := http.ReadResponse(bufio.NewReader(stream.Reader), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	defer stream.Reader.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	rawDigest, err := base64.RawStdEncoding.DecodeString("FFLmryM0N2S+0JJ3P+H4YA89iwmLe68tvlkzIGz3G60")
	if err != nil {
		t.Fatal(err)
	}

	res := sha256.Sum256(b)

	if !bytes.Equal(rawDigest, res[:]) {
		fmt.Println("invalid check")
		t.Error("FASDFASDFASDFASDFASFADSF")
	}

	fmt.Println(string(b))

}
