package hops_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/hops"
	"github.com/robogg133/gonion/internal/window"
	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/crypto"
)

func mustRunning(t *testing.T, key, dig []byte) *crypto.RunningValues {
	t.Helper()
	rv, err := crypto.NewRunningValues(key, dig)
	if err != nil {
		t.Fatalf("NewRunningValues: %v", err)
	}
	return rv
}

func randomKeyMaterial(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

type hopKeys struct {
	Kf, Df, Kb, Db []byte
}

func genHopKeys(t *testing.T) hopKeys {
	t.Helper()
	return hopKeys{
		Kf: randomKeyMaterial(t, 16),
		Df: randomKeyMaterial(t, 20),
		Kb: randomKeyMaterial(t, 16),
		Db: randomKeyMaterial(t, 20),
	}
}

func clientHopFromKeys(t *testing.T, ctx context.Context, k hopKeys) *hops.Hop {
	t.Helper()
	fwd := mustRunning(t, k.Kf, k.Df)
	bwd := mustRunning(t, k.Kb, k.Db)
	return hops.NewHop(ctx, relay.NewDataCellCoder(bwd, fwd), window.NewWindow(1000, 100), window.NewWindow(1000, 100))
}

// serverCoder uses swapped directions so it can encrypt toward the client
// and peel client outbound layers.
func serverCoderFromKeys(t *testing.T, k hopKeys) *relay.RelayCellCoder {
	t.Helper()
	fwd := mustRunning(t, k.Kb, k.Db)
	bwd := mustRunning(t, k.Kf, k.Df)
	return relay.NewDataCellCoder(bwd, fwd)
}

func TestChain_Empty(t *testing.T) {
	var c hops.Chain

	if c.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", c.Len())
	}
	if c.Guard() != nil || c.Exit() != nil || c.At(0) != nil {
		t.Fatal("expected nil accessors on empty chain")
	}

	_, _, err := c.UnmarshalMessage(make([]byte, cells.CELL_BODY_LEN))
	if !errors.Is(err, hops.ErrCantDecrypt) {
		t.Fatalf("UnmarshalMessage empty: %v, want ErrCantDecrypt", err)
	}

	_, err = c.MarshalMessage(&relay.BeginDirCell{StreamID: 1}, 0)
	if err == nil {
		t.Fatal("MarshalMessage on empty chain should fail")
	}
}

func TestChain_AppendGuardExitAt(t *testing.T) {
	ctx := context.Background()
	var c hops.Chain

	h0 := clientHopFromKeys(t, ctx, genHopKeys(t))
	h1 := clientHopFromKeys(t, ctx, genHopKeys(t))
	h2 := clientHopFromKeys(t, ctx, genHopKeys(t))

	c.Append(h0)
	if c.Len() != 1 || c.Guard() != h0 || c.Exit() != h0 {
		t.Fatal("single hop should be both guard and exit")
	}

	c.Append(h1)
	c.Append(h2)

	if c.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", c.Len())
	}
	if c.Guard() != h0 || c.Exit() != h2 || c.At(1) != h1 {
		t.Fatal("accessor mismatch")
	}
	if c.At(-1) != nil || c.At(3) != nil {
		t.Fatal("At out of range should be nil")
	}
}

func TestChain_MarshalInvalidDestination(t *testing.T) {
	ctx := context.Background()
	var c hops.Chain
	c.Append(clientHopFromKeys(t, ctx, genHopKeys(t)))

	for _, dst := range []int{-1, 1, 99} {
		if _, err := c.MarshalMessage(&relay.BeginDirCell{StreamID: 1}, dst); err == nil {
			t.Fatalf("dst=%d: expected error", dst)
		}
	}
}

func TestChain_SingleHop_RoundTrip_BeginDir(t *testing.T) {
	ctx := context.Background()
	k := genHopKeys(t)

	var client hops.Chain
	client.Append(clientHopFromKeys(t, ctx, k))

	out, err := client.MarshalMessage(&relay.BeginDirCell{StreamID: 7}, 0)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	if len(out) != cells.CELL_BODY_LEN {
		t.Fatalf("body len = %d, want %d", len(out), cells.CELL_BODY_LEN)
	}

	server := serverCoderFromKeys(t, k)
	plain, err := server.Unmarshal(append([]byte(nil), out...))
	if err != nil {
		t.Fatalf("server Unmarshal: %v", err)
	}
	if plain.ID() != relay.COMMAND_BEGIN_DIR || plain.GetStreamID() != 7 {
		t.Fatalf("server saw %#v", plain)
	}

	inbound, err := server.Marshal(&relay.ConnectedCell{StreamID: 7})
	if err != nil {
		t.Fatalf("server Marshal: %v", err)
	}

	from, cell, err := client.UnmarshalMessage(append([]byte(nil), inbound...))
	if err != nil {
		t.Fatalf("client UnmarshalMessage: %v", err)
	}
	if from != 0 {
		t.Fatalf("fromHop = %d, want 0", from)
	}
	if cell.ID() != relay.COMMAND_CONNECTED || cell.GetStreamID() != 7 {
		t.Fatalf("client saw %#v", cell)
	}
}

func TestChain_ThreeHop_ExitDestination(t *testing.T) {
	ctx := context.Background()
	keys := []hopKeys{genHopKeys(t), genHopKeys(t), genHopKeys(t)}

	var client hops.Chain
	for _, k := range keys {
		client.Append(clientHopFromKeys(t, ctx, k))
	}

	want := &relay.DataCell{StreamID: 42, Payload: []byte("hello-from-exit")}
	out, err := client.MarshalMessage(want, 2)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}

	body := append([]byte(nil), out...)
	for i, k := range keys {
		srv := serverCoderFromKeys(t, k)
		srv.Backwards.XORKeyStream(body, body)
		if relay.IsDecrypted(body) {
			cell, err := srv.UnmarshalPlain(body)
			if err != nil {
				t.Fatalf("hop %d UnmarshalPlain: %v", i, err)
			}
			if i != 2 {
				t.Fatalf("recognized at hop %d, want only exit (2)", i)
			}
			got := cell.(*relay.DataCell)
			if got.GetStreamID() != 42 || !bytes.Equal(got.Payload, want.Payload) {
				t.Fatalf("payload mismatch: sid=%d payload=%q", got.GetStreamID(), got.Payload)
			}
			return
		}
	}
	t.Fatal("exit never recognized cell")
}

func TestChain_ThreeHop_MiddleDestination(t *testing.T) {
	ctx := context.Background()
	keys := []hopKeys{genHopKeys(t), genHopKeys(t), genHopKeys(t)}

	var client hops.Chain
	for _, k := range keys {
		client.Append(clientHopFromKeys(t, ctx, k))
	}

	out, err := client.MarshalMessage(&relay.BeginDirCell{StreamID: 0}, 1)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}

	body := append([]byte(nil), out...)
	for i := 0; i <= 1; i++ {
		srv := serverCoderFromKeys(t, keys[i])
		srv.Backwards.XORKeyStream(body, body)
		if relay.IsDecrypted(body) {
			if i != 1 {
				t.Fatalf("recognized at hop %d, want 1", i)
			}
			cell, err := srv.UnmarshalPlain(body)
			if err != nil {
				t.Fatalf("UnmarshalPlain: %v", err)
			}
			if cell.ID() != relay.COMMAND_BEGIN_DIR {
				t.Fatalf("cmd = %d", cell.ID())
			}
			return
		}
	}
	t.Fatal("middle hop did not recognize cell")
}

func TestChain_InboundFromExit_RoundTrip(t *testing.T) {
	ctx := context.Background()
	keys := []hopKeys{genHopKeys(t), genHopKeys(t), genHopKeys(t)}

	var client hops.Chain
	servers := make([]*relay.RelayCellCoder, len(keys))
	for i, k := range keys {
		client.Append(clientHopFromKeys(t, ctx, k))
		servers[i] = serverCoderFromKeys(t, k)
	}

	payload := []byte("response-body")
	body, err := servers[2].Marshal(&relay.DataCell{StreamID: 9, Payload: payload})
	if err != nil {
		t.Fatalf("exit marshal: %v", err)
	}
	for i := 1; i >= 0; i-- {
		servers[i].Forwards.XORKeyStream(body, body)
	}

	from, cell, err := client.UnmarshalMessage(append([]byte(nil), body...))
	if err != nil {
		t.Fatalf("UnmarshalMessage: %v", err)
	}
	if from != 2 {
		t.Fatalf("fromHop = %d, want 2", from)
	}
	got := cell.(*relay.DataCell)
	if got.GetStreamID() != 9 || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("got sid=%d payload=%q", got.GetStreamID(), got.Payload)
	}
}

func TestChain_InboundFromGuardOnly(t *testing.T) {
	ctx := context.Background()
	keys := []hopKeys{genHopKeys(t), genHopKeys(t)}

	var client hops.Chain
	for _, k := range keys {
		client.Append(clientHopFromKeys(t, ctx, k))
	}

	srv0 := serverCoderFromKeys(t, keys[0])
	body, err := srv0.Marshal(&relay.SendMeCell{
		StreamID:        0,
		Version:         1,
		Sha1ForLastCell: [20]byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	from, cell, err := client.UnmarshalMessage(append([]byte(nil), body...))
	if err != nil {
		t.Fatalf("UnmarshalMessage: %v", err)
	}
	if from != 0 {
		t.Fatalf("fromHop = %d, want 0", from)
	}
	sm := cell.(*relay.SendMeCell)
	if sm.Version != 1 || sm.Sha1ForLastCell != [20]byte{1, 2, 3} {
		t.Fatalf("sendme mismatch: %+v", sm)
	}
}

func TestChain_DecryptFailure_WrongKeys(t *testing.T) {
	ctx := context.Background()
	var client hops.Chain
	client.Append(clientHopFromKeys(t, ctx, genHopKeys(t)))

	other := serverCoderFromKeys(t, genHopKeys(t))
	body, err := other.Marshal(&relay.BeginDirCell{StreamID: 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, _, err = client.UnmarshalMessage(body)
	if !errors.Is(err, hops.ErrCantDecrypt) {
		t.Fatalf("err = %v, want ErrCantDecrypt", err)
	}
}

func TestChain_DecryptFailure_CorruptBody(t *testing.T) {
	ctx := context.Background()
	var client hops.Chain
	client.Append(clientHopFromKeys(t, ctx, genHopKeys(t)))

	body := make([]byte, cells.CELL_BODY_LEN)
	rand.Read(body)

	_, _, err := client.UnmarshalMessage(body)
	if !errors.Is(err, hops.ErrCantDecrypt) {
		t.Fatalf("err = %v, want ErrCantDecrypt", err)
	}
}

func TestChain_MarshalAdvancesCipher(t *testing.T) {
	ctx := context.Background()
	var client hops.Chain
	for range 3 {
		client.Append(clientHopFromKeys(t, ctx, genHopKeys(t)))
	}

	cell := &relay.DataCell{StreamID: 3, Payload: []byte("abc")}
	b1, err := client.MarshalMessage(cell, 2)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := client.MarshalMessage(cell, 2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b1, b2) {
		t.Fatal("expected different ciphertexts after digest/ctr advance")
	}
	if !bytes.Equal(cell.Payload, []byte("abc")) {
		t.Fatal("payload should remain intact")
	}
}

func TestHop_SendMeNotify(t *testing.T) {
	ctx := context.Background()
	h := clientHopFromKeys(t, ctx, genHopKeys(t))

	select {
	case <-h.SendMe():
		t.Fatal("channel should be empty")
	default:
	}

	h.NotifySendMe()
	select {
	case <-h.SendMe():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting NotifySendMe")
	}

	h.NotifySendMe()
	h.NotifySendMe()
	done := make(chan struct{})
	go func() {
		h.NotifySendMe()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("NotifySendMe blocked")
	}
}

func TestHop_Cancel(t *testing.T) {
	ctx := context.Background()
	h := clientHopFromKeys(t, ctx, genHopKeys(t))

	cause := errors.New("hop teardown")
	h.Cancel(cause)

	select {
	case <-h.Ctx().Done():
	case <-time.After(time.Second):
		t.Fatal("ctx not cancelled")
	}
	if !errors.Is(context.Cause(h.Ctx()), cause) {
		t.Fatalf("cause = %v", context.Cause(h.Ctx()))
	}
}

func TestHop_WindowsArePointers(t *testing.T) {
	ctx := context.Background()
	rcv := window.NewWindow(10, 5)
	snd := window.NewWindow(10, 5)
	k := genHopKeys(t)
	fwd := mustRunning(t, k.Kf, k.Df)
	bwd := mustRunning(t, k.Kb, k.Db)
	h := hops.NewHop(ctx, relay.NewDataCellCoder(bwd, fwd), rcv, snd)

	if h.Recv() != rcv || h.Send() != snd {
		t.Fatal("windows must be stored by pointer identity")
	}
	rcv.Subtract(5)
	select {
	case <-h.Recv().Get():
	default:
		t.Fatal("expected window trigger on shared pointer")
	}
}

func TestChain_DataCell_DigestSetOnMarshal(t *testing.T) {
	ctx := context.Background()
	var client hops.Chain
	client.Append(clientHopFromKeys(t, ctx, genHopKeys(t)))

	cell := &relay.DataCell{StreamID: 1, Payload: []byte("x")}
	if cell.Digest() != [20]byte{} {
		t.Fatal("digest should start zero")
	}
	if _, err := client.MarshalMessage(cell, 0); err != nil {
		t.Fatal(err)
	}
	if cell.Digest() == [20]byte{} {
		t.Fatal("Marshal should populate DataCell digest")
	}
}

func TestChain_TableDrivenDestinations(t *testing.T) {
	ctx := context.Background()
	const n = 4
	keys := make([]hopKeys, n)
	for i := range n {
		keys[i] = genHopKeys(t)
	}

	for dst := 0; dst < n; dst++ {
		t.Run(fmt.Sprintf("dst_%d", dst), func(t *testing.T) {
			var c hops.Chain
			srvs := make([]*relay.RelayCellCoder, n)
			for i := range n {
				c.Append(clientHopFromKeys(t, ctx, keys[i]))
				srvs[i] = serverCoderFromKeys(t, keys[i])
			}

			sid := uint16(100 + dst)
			out, err := c.MarshalMessage(&relay.BeginDirCell{StreamID: sid}, dst)
			if err != nil {
				t.Fatal(err)
			}
			body := append([]byte(nil), out...)
			recognized := -1
			for i := 0; i <= dst; i++ {
				srvs[i].Backwards.XORKeyStream(body, body)
				if relay.IsDecrypted(body) {
					recognized = i
					cell, err := srvs[i].UnmarshalPlain(body)
					if err != nil {
						t.Fatal(err)
					}
					if cell.GetStreamID() != sid {
						t.Fatalf("sid = %d", cell.GetStreamID())
					}
					break
				}
			}
			if recognized != dst {
				t.Fatalf("recognized=%d want %d", recognized, dst)
			}
		})
	}
}
