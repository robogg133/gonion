package common

import "testing"

func TestProtocolVersionsUseWireNumbers(t *testing.T) {
	// tor-spec 9: HSDir=2 serves v3 descriptors; HSDir=1 alone does not.
	var r RouterStatus
	if err := parseRouterItem(ConsensusFlavorMicrodesc, &r, []string{"pr", "HSDir=1", "HSIntro=4-5", "HSRend=2"}); err != nil {
		t.Fatal(err)
	}
	if r.ProtoVersions.HSDir.CheckIsTrue(VERSION_2) || !r.ProtoVersions.HSDir.CheckIsTrue(VERSION_1) || !r.ProtoVersions.HSIntro.CheckIsTrue(VERSION_4) || !r.ProtoVersions.HSRend.CheckIsTrue(VERSION_2) {
		t.Fatal("protocol bitmap does not match wire versions")
	}
}
