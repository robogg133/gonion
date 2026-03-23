package tests

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	gonion2 "git.servidordomal.fun/robogg133/gonion-rewrite"
)

func TestMicrodesc(t *testing.T) {
	conn, err := gonion2.NewConn("38.102.127.252:9004")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created conn")

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created circuit")

	stream, err := circuit.NewStream("dir")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Stream open")

	blobDigest, err := base64.RawStdEncoding.DecodeString("XqUDv1SH3bF+mozbmkZxGbaNn3MqaUj21GAnY4UTvHo")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("given sha256sum: %x\n", blobDigest)

	req, err := http.NewRequest("GET", fmt.Sprintf(gonion2.HTTP_PATH_MICRODESCRIPTOR_DIR_FORMAT, "XqUDv1SH3bF+mozbmkZxGbaNn3MqaUj21GAnY4UTvHo"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(stream); err != nil {
		t.Fatal(err)
	}
	t.Log("Payload wrote")

	t.Log("Starting to read")

	resp, err := http.ReadResponse(bufio.NewReader(stream.Reader), req)
	if err != nil {
		t.Fatal(err)
	}

	desc, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(desc)

	if !bytes.Equal(sum[:], blobDigest) {
		t.Fatal("unequivalent sha256sum")
	}

	os.WriteFile("microdesc_dir.txt", desc, 0777)

}
