package common_test

import (
	"testing"

	cells "github.com/robogg133/gonion/pkg/cells/base"
	"github.com/robogg133/gonion/pkg/common"
)

func TestDestroyGetReasonS_Known(t *testing.T) {
	cases := []struct {
		reason uint8
		want   string
	}{
		{cells.DESTROY_REASON_NONE, cells.DESTROY_REASON_NONE_MSG},
		{cells.DESTROY_REASON_PROTCOL, cells.DESTROY_REASON_PROTCOL_MSG},
		{cells.DESTROY_REASON_TIMEOUT, cells.DESTROY_REASON_TIMEOUT_MSG},
		{cells.DESTROY_REASON_NOSUCHSERVICE, cells.DESTROY_REASON_NOSUCHSERVICE_MSG},
	}
	for _, tc := range cases {
		got := common.DestroyGetReasonS(tc.reason)
		if got != tc.want {
			t.Fatalf("reason %d: got %q want %q", tc.reason, got, tc.want)
		}
	}
}

func TestDestroyGetReasonS_Unknown(t *testing.T) {
	if common.DestroyGetReasonS(255) != "" {
		t.Fatal("unknown reason should be empty")
	}
}
