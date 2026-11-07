package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSeparateCommands(t *testing.T) {
	for _, tc := range []struct{ name, flag string }{{"obfs4", "-iatmode"}, {"meek", "-front"}, {"snowflake", "-ice"}, {"webtunnel", "-servername"}} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command("go", "run", "./"+tc.name, "-h").CombinedOutput()
			if err != nil {
				t.Fatalf("help: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), tc.flag) || strings.Contains(string(out), "-transport ") {
				t.Fatalf("incorrect command flags: %s", out)
			}
			out, err = exec.Command("go", "run", "./"+tc.name).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "provide -") {
				t.Fatalf("missing parameters must fail before network: %v\n%s", err, out)
			}
		})
	}
}
