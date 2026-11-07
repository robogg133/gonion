package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/embed"
	"github.com/robogg133/gonion/pkg/path"
)

// Controlled-network (chutney) coverage for long-running service behavior.
//
// One shared chutney network backs three flows in one process:
//
//	a. a fresh ephemeral onion service through embed.Listen, then a Gonion
//	   client dial and a 64 KiB round trip;
//	b. restart persistence: both are closed, a fresh embed client bootstraps
//	   with the SAME file-backed guard state and the SAME file-backed
//	   NextRevision counter, the service republishes and the client connects
//	   again;
//	c. introduction replacement: the relay that carried one of the service's
//	   introductions is killed (chutney-style: the relay's own process is
//	   killed), and the service must establish a replacement introduction on
//	   another relay within a bounded wait, after which the client connects.
//
// The chutney directory authorities are used as the trusted consensus anchors
// through embed.Options.Authorities, so no public authority is contacted and no
// identity check is skipped: the bootstrap relay and every traffic guard are
// still pinned by CERTS. Relay identification for flow (c) comes from the
// chutney relays' own info.log ESTABLISH_INTRO lines, not from any test hook.
//
// The network is the basic-min topology with two required adaptations:
//
//   - one IPv4 /16 per node, because Gonion enforces path-spec subnet diversity
//     and basic-min puts every node on 127.0.0.1, so every candidate circuit
//     conflicts;
//   - a plain non-exit relay instead of the exit relay, because a consensus
//     from only these authorities gives a Guard+Exit relay guard weight
//     Wgd=0, which the public guard manager cannot sample. Onion client and
//     service circuits never need an exit relay.
//
// The consensus must outlive the flows, so the network is built with
// CHUTNEY_V3_AUTH_VOTING_INTERVAL_SECONDS=600 (valid-until = valid-after + 20
// minutes). Chutney's default 20 second interval makes a consensus valid for
// only 40 seconds, which is shorter than the one minute service renewal tick
// that flow (c) needs. Refreshing an expired consensus is deliberately outside
// this test: with the current tree that refresh fails on this network (the
// bootstrap and the refresh both create a one-hop CREATE_FAST circuit with
// circuit ID 1, and Circuit.Close never sends DESTROY, so the relay reports
// "Received CREATE cell (circID 2147483649) for known circ. Dropping" and the
// refresh dies with "protocol violation: expected CREATED_FAST, got command 4").
// A run that outlives its consensus therefore fails; that is a real defect in
// the refresh path, not evidence about the service flows covered here.
//
// Because the authorities read the bandwidth file only when they vote, the very
// first consensus of a fresh network has "w Bandwidth=0" for every relay and
// Gonion then selects nothing. Let one consensus period pass (the second
// consensus carries real bandwidths) before running the test.
//
// Explicitly NOT covered here: SRV-period rollover, consensus-epoch simulation,
// consensus refresh after expiry, and guard-spec retry-race scenarios. This is a
// controlled local network, so it is not evidence about the public Tor network.
//
// Opt-in only; the default suite must skip it. It needs an already bootstrapped
// chutney network built from this script (save it as /tmp/opencode/gonion-net.py):
//
//	Authority = Node(tag="a", authority=1, relay=1)
//	NonExitRelay = Node(tag="r", relay=1)
//	Client = Node(tag="c", client=1)
//	ConfigureNodes([
//	    Node(tag="a", authority=1, relay=1, ip="127.0.0.1"),
//	    Node(tag="a", authority=1, relay=1, ip="127.1.0.1"),
//	    Node(tag="a", authority=1, relay=1, ip="127.2.0.1"),
//	    Node(tag="a", authority=1, relay=1, ip="127.3.0.1"),
//	    Node(tag="r", relay=1, ip="127.4.0.1"),
//	    Node(tag="c", client=1, ip="127.5.0.1"),
//	])
//
//	git clone https://gitlab.torproject.org/tpo/core/chutney.git
//	CHUTNEY_V3_AUTH_VOTING_INTERVAL_SECONDS=600 chutney --data-dir /tmp/opencode/chutney-net init --net-from-script-path /tmp/opencode/gonion-net.py
//	CHUTNEY_V3_AUTH_VOTING_INTERVAL_SECONDS=600 chutney --data-dir /tmp/opencode/chutney-net bootstrap
//
// then run:
//
//	GONION_TEST_CHUTNEY=1 go test ./internal/tests -run '^TestChutneyLongRunningService$' -count=1 -v -timeout 13m
//
// Flow (c) kills and then restarts one relay, so the network stays usable for
// repeated runs; it finds that process through /proc, which makes the test
// Linux-only.
func TestChutneyLongRunningService(t *testing.T) {
	if os.Getenv("GONION_TEST_CHUTNEY") != "1" {
		t.Skip("set GONION_TEST_CHUTNEY=1 to run the controlled chutney-network service test")
	}
	network := loadChutneyNetwork(t, chutneyNodesDir(t))
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()

	workDir := t.TempDir()
	guardFile := filepath.Join(workDir, "guards.json")
	revisionFile := filepath.Join(workDir, "revision")
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity)

	// Flow (a): fresh ephemeral service and a Gonion client round trip.
	client := network.newClient(t, ctx, guardFile)
	listener := listenService(t, ctx, client, identity, revisionFile)
	roundTrip(t, ctx, client, listener, 1)
	if data, err := os.ReadFile(guardFile); err != nil || len(data) == 0 {
		t.Fatalf("guard state was not persisted for the restart: bytes=%d err=%v", len(data), err)
	}

	// Flow (b): restart with the same persisted guard state and revisions.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	beforeRestart := network.introCounts() // Baseline: only the restarted service's introductions count.
	revisionBefore, err := os.ReadFile(revisionFile)
	if err != nil {
		t.Fatal(err)
	}
	client = network.newClient(t, ctx, guardFile)
	listener = listenService(t, ctx, client, identity, revisionFile)
	revisionAfter, err := os.ReadFile(revisionFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(revisionAfter, revisionBefore) <= 0 {
		t.Fatalf("service republication on restart did not advance the persisted revision: before=%q after=%q", revisionBefore, revisionAfter)
	}
	roundTrip(t, ctx, client, listener, 2)

	// Flow (c): retire one introduction-point relay and wait for its replacement.
	intros := network.gainedIntroductions(beforeRestart)
	if len(intros) == 0 {
		t.Fatalf("no relay logged an ESTABLISH_INTRO for the restarted service; cannot retire an introduction")
	}
	victim := intros[0]
	for _, node := range intros {
		if !node.authority { // Keep the directory-authority quorum intact when possible.
			victim = node
			break
		}
	}
	beforeStop := network.introCounts()
	t.Logf("retiring introduction relay %s (orport=%s) out of %v", victim.nick, victim.orAddr, introNicks(intros))
	// Restore the relay even when this flow fails, so repeated runs keep the network.
	t.Cleanup(func() { restartNode(t, network.torBinary, victim) })
	stopNode(t, victim)
	replaced := network.waitForReplacement(ctx, victim, beforeStop, 4*time.Minute)
	if !replaced {
		t.Fatalf("service did not establish a replacement introduction within the bounded wait after stopping %s", victim.nick)
	}
	t.Logf("service replaced the retired introduction")
	roundTrip(t, ctx, client, listener, 3)
}

// roundTrip dials the service with a Gonion client and echoes a payload
// through the same circuit topology (client guard/rendezvous, service
// introduction/rendezvous).
func roundTrip(t *testing.T, ctx context.Context, client *embed.Client, listener *embed.Listener, phase int) {
	t.Helper()
	const size = 64 << 10
	conn, err := client.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("phase %d client dial: %v (listener maintenance: %v)", phase, err, listener.Err())
	}
	defer conn.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatalf("phase %d accept: %v", phase, err)
	}
	defer server.Close()
	deadline := time.Now().Add(2 * time.Minute)
	_ = conn.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	echo := make(chan error, 1)
	go func() {
		received := make([]byte, size)
		if _, err := io.ReadFull(server, received); err != nil {
			echo <- err
			return
		}
		if !bytes.Equal(received, payload) {
			echo <- errors.New("service received corrupted application data")
			return
		}
		_, err := server.Write(received)
		echo <- err
	}()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("phase %d upload: %v", phase, err)
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("phase %d echo corrupted or truncated: %v", phase, err)
	}
	if err := <-echo; err != nil {
		t.Fatalf("phase %d service echo: %v", phase, err)
	}
	t.Logf("phase %d: 64 KiB verified in each direction", phase)
}

func listenService(t *testing.T, ctx context.Context, client *embed.Client, identity ed25519.PrivateKey, revisionFile string) *embed.Listener {
	t.Helper()
	initCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	listener, err := client.Listen(initCtx, embed.ServiceOptions{Identity: identity, Port: 80, NextRevision: fileRevision(revisionFile)})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Shutdown() })
	return listener
}

// fileRevision is a caller-owned file-backed NextRevision: it reserves a
// strictly increasing revision and persists it before returning.
func fileRevision(name string) func(context.Context, [32]byte) (uint64, error) {
	return func(ctx context.Context, _ [32]byte) (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var current uint64
		if raw, err := os.ReadFile(name); err == nil {
			if _, err := fmt.Sscan(strings.TrimSpace(string(raw)), &current); err != nil {
				return 0, fmt.Errorf("revision state: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return 0, err
		}
		current++
		if err := os.WriteFile(name, []byte(strconv.FormatUint(current, 10)), 0600); err != nil {
			return 0, err
		}
		return current, nil
	}
}

// fileGuards mirrors examples/embed/internal/guardstate: atomic, durable,
// caller-owned public-guard state.
func fileGuards(name string) (*path.GuardManager, error) {
	return path.NewGuardManager(context.Background(), path.GuardPersistence{
		Load: func(ctx context.Context) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			data, err := os.ReadFile(name)
			if err != nil && os.IsNotExist(err) {
				return nil, nil
			}
			return data, err
		},
		Save: func(ctx context.Context, data []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			file, err := os.CreateTemp(filepath.Dir(name), ".gonion-guards-*")
			if err != nil {
				return err
			}
			tmp := file.Name()
			defer os.Remove(tmp)
			if err = file.Chmod(0600); err == nil {
				if _, err = file.Write(data); err == nil {
					err = file.Sync()
				}
			}
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			if err := os.Rename(tmp, name); err != nil {
				return err
			}
			dir, err := os.Open(filepath.Dir(name))
			if err != nil {
				return err
			}
			defer dir.Close()
			return dir.Sync()
		},
	})
}

// chutneyNetwork is the subset of a running chutney network this test needs.
type chutneyNetwork struct {
	dir         string
	torBinary   string
	authorities []chutneyNode
	relays      []chutneyNode
	bootstrap   chutneyNode
}

type chutneyNode struct {
	nick      string
	dir       string
	torrc     string
	infoLog   string
	pidFile   string
	orAddr    string
	rsa       [20]byte // Relay/orport RSA identity, used to pin the bootstrap relay.
	v3ident   [20]byte // v3 directory-authority identity, used as a consensus trust anchor.
	authority bool
}

// newClient bootstraps a Gonion client against the local chutney authorities.
// The bootstrap relay identity is pinned and the trust anchors are the chutney
// authorities; no identity check is disabled.
func (n chutneyNetwork) newClient(t *testing.T, ctx context.Context, guardFile string) *embed.Client {
	t.Helper()
	guards, err := fileGuards(guardFile)
	if err != nil {
		t.Fatal(err)
	}
	pins := make([][20]byte, len(n.authorities))
	for i, authority := range n.authorities {
		pins[i] = authority.v3ident
	}
	opts := embed.DefaultOptions()
	opts.Guards = guards
	opts.Authorities = pins
	opts.BootstrapIdentity = n.bootstrap.rsa
	opts.ORDialer = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", n.bootstrap.orAddr)
	}
	client, err := embed.New(ctx, opts)
	if err != nil {
		t.Fatalf("embed.New against chutney authority %s: %v", n.bootstrap.orAddr, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// introCounts returns the number of ESTABLISH_INTRO requests each relay has
// logged so far, used as a baseline for the next phase.
func (n chutneyNetwork) introCounts() map[string]int {
	counts := make(map[string]int, len(n.relays))
	for _, node := range n.relays {
		counts[node.nick] = introCount(node)
	}
	return counts
}

func (n chutneyNetwork) gainedIntroductions(baseline map[string]int) []chutneyNode {
	var out []chutneyNode
	for _, node := range n.relays {
		if introCount(node) > baseline[node.nick] {
			out = append(out, node)
		}
	}
	return out
}

// waitForReplacement polls the other relays until one logs a new
// ESTABLISH_INTRO, proving the service established a fresh introduction after
// the retired one died.
func (n chutneyNetwork) waitForReplacement(ctx context.Context, victim chutneyNode, baseline map[string]int, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		for _, node := range n.relays {
			if node.nick == victim.nick {
				continue
			}
			if introCount(node) > baseline[node.nick] {
				return true
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

func introNicks(nodes []chutneyNode) []string {
	nicks := make([]string, len(nodes))
	for i, node := range nodes {
		nicks[i] = node.nick
	}
	return nicks
}

const introLogMarker = "Received an ESTABLISH_INTRO request on circuit"

func introCount(node chutneyNode) int {
	data, err := os.ReadFile(node.infoLog)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), introLogMarker)
}

// relayPID finds the tor process that runs this node's torrc. Chutney writes the
// pid file for the nodes it started, but tor does not rewrite it under Sandbox,
// so a relay this test restarted is located by command line instead. The command
// line is always verified so a stale or reused pid never targets another process.
func relayPID(node chutneyNode) (int, bool) {
	if raw, err := os.ReadFile(node.pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && runsNodeTorrc(pid, node.torrc) {
			return pid, true
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !runsNodeTorrc(pid, node.torrc) {
			continue
		}
		return pid, true
	}
	return 0, false
}

func runsNodeTorrc(pid int, torrc string) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ReplaceAll(string(data), "\x00", " "), torrc)
}

// stopNode retires a running chutney node the way chutney does: the relay's own
// process is killed, so its ORPort stops accepting.
func stopNode(t *testing.T, node chutneyNode) {
	t.Helper()
	pid, ok := relayPID(node)
	if !ok {
		t.Fatalf("no running tor process for relay %s", node.nick)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Kill(); err != nil {
		t.Fatalf("kill %s (%d): %v", node.nick, pid, err)
	}
	t.Logf("stopped relay %s (pid %d)", node.nick, pid)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", node.orAddr, time.Second)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("relay %s still accepts connections after being killed", node.nick)
}

// restartNode brings the retired relay back so the shared network survives
// repeated runs. Tor keeps the node's identity keys, so its fingerprint is
// unchanged and it rejoins the consensus without operator action. The pid file
// is refreshed by hand because tor skips it under Sandbox; without that, the
// operator's `chutney stop` would not reap the restarted process.
func restartNode(t *testing.T, torBinary string, node chutneyNode) {
	t.Helper()
	cmd := exec.Command(torBinary, "-f", node.torrc)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		t.Logf("warning: could not restart relay %s (%v); rerun `chutney start` before the next run", node.nick, err)
		return
	}
	_ = os.WriteFile(node.pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
	_ = cmd.Process.Release()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", node.orAddr, time.Second)
		if err == nil {
			_ = conn.Close()
			t.Logf("relay %s restarted", node.nick)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("warning: relay %s did not accept connections within 90s; rerun `chutney start` before the next run", node.nick)
}

// loadChutneyNetwork reads the node state of a bootstrapped chutney network.
func loadChutneyNetwork(t *testing.T, dir string) chutneyNetwork {
	t.Helper()
	// Chutney's `nodes` entry is a symlink; tor is started with resolved paths,
	// so resolve here to compare command lines and to read the live node state.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	dir = resolved
	network := chutneyNetwork{dir: dir, torBinary: "tor"}
	if binary, err := exec.LookPath("tor"); err == nil {
		network.torBinary = binary
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !chutneyNodeDir.MatchString(entry.Name()) {
			continue
		}
		node, err := readChutneyNode(dir, entry.Name())
		if err != nil {
			continue // Client-only nodes have no ORPort and are not used here.
		}
		network.relays = append(network.relays, node)
		if node.authority {
			network.authorities = append(network.authorities, node)
		}
	}
	if len(network.authorities) < 3 {
		t.Fatalf("chutney network in %s has %d directory authorities; at least 3 are needed", dir, len(network.authorities))
	}
	if len(network.relays) < 4 {
		t.Fatalf("chutney network in %s has %d relays; 3-hop onion paths need more", dir, len(network.relays))
	}
	network.bootstrap = network.authorities[0]
	return network
}

func readChutneyNode(dir, name string) (chutneyNode, error) {
	nodeDir := filepath.Join(dir, name)
	torrcPath := filepath.Join(nodeDir, "torrc")
	torrc, err := os.ReadFile(torrcPath)
	if err != nil {
		return chutneyNode{}, err
	}
	node := chutneyNode{nick: name, dir: nodeDir, torrc: torrcPath, infoLog: filepath.Join(nodeDir, "info.log"), pidFile: filepath.Join(nodeDir, "pid")}
	for line := range strings.Lines(string(torrc)) {
		line = strings.TrimSpace(line)
		if addr, ok := strings.CutPrefix(line, "OrPort "); ok {
			node.orAddr = strings.TrimSpace(addr)
		}
		if strings.HasPrefix(line, "V3AuthoritativeDirectory 1") {
			node.authority = true
		}
	}
	if node.orAddr == "" {
		return chutneyNode{}, errors.New("node has no ORPort")
	}
	if _, _, err := net.SplitHostPort(node.orAddr); err != nil {
		return chutneyNode{}, err
	}
	fingerprint, err := os.ReadFile(filepath.Join(nodeDir, "fingerprint"))
	if err != nil {
		return chutneyNode{}, err
	}
	fields := strings.Fields(string(fingerprint))
	if len(fields) != 2 {
		return chutneyNode{}, errors.New("invalid chutney fingerprint file")
	}
	raw, err := hex.DecodeString(fields[1])
	if err != nil || len(raw) != 20 {
		return chutneyNode{}, errors.New("invalid chutney fingerprint")
	}
	copy(node.rsa[:], raw)
	if node.authority {
		// The authority certificate's fingerprint field is the v3 authority
		// identity that signs the consensus, not the relay's RSA identity.
		cert, err := os.ReadFile(filepath.Join(nodeDir, "keys", "authority_certificate"))
		if err != nil {
			return chutneyNode{}, err
		}
		for line := range strings.Lines(string(cert)) {
			value, ok := strings.CutPrefix(strings.TrimSpace(line), "fingerprint ")
			if !ok {
				continue
			}
			decoded, err := hex.DecodeString(strings.TrimSpace(value))
			if err != nil || len(decoded) != 20 {
				return chutneyNode{}, errors.New("invalid chutney authority identity")
			}
			copy(node.v3ident[:], decoded)
		}
		if node.v3ident == ([20]byte{}) {
			return chutneyNode{}, errors.New("missing chutney authority identity")
		}
	}
	return node, nil
}

// Chutney names node directories after the node tag, e.g. "000a" or "004r".
var chutneyNodeDir = regexp.MustCompile(`^\d+[a-z]+$`)

func chutneyNodesDir(t *testing.T) string {
	t.Helper()
	var candidates []string
	if dir := os.Getenv("GONION_CHUTNEY_NET_DIR"); dir != "" {
		candidates = append(candidates, dir)
	}
	if dir := os.Getenv("CHUTNEY_DATA_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "nodes"))
	}
	candidates = append(candidates, filepath.Join("/tmp/opencode", "chutney-net", "nodes"))
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	t.Fatalf("no chutney network found in %s; set GONION_CHUTNEY_NET_DIR or generate one with "+
		"`chutney --data-dir /tmp/opencode/chutney-net init --net basic-min` and `... bootstrap`", strings.Join(candidates, ", "))
	return ""
}
