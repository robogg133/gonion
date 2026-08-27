package mem

import (
	"reflect"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

func TestStoreGet(t *testing.T) {
	st := New()
	if got, _ := st.GetConsensus(); got != nil {
		t.Fatalf("expected nil before store, got %+v", got)
	}

	c := &common.Consensus{ValidUntil: time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC)}
	if err := st.StoreConsensus(c); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetConsensus()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("got %+v, want %+v", got, c)
	}
}