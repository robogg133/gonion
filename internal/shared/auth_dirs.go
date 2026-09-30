package shared

type DirectoryAuthority struct {
	Nickname    string
	IPv4        string
	DirPort     uint16
	ORPort      uint16
	IPv6        string
	IPv6Port    uint16
	V3Ident     string // Ed25519, hex (64 chars)
	Fingerprint string // RSA identity, hex (40 chars)
	IsBridge    bool
}

var Authorities = []DirectoryAuthority{}
