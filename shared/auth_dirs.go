/* timestamp=1769922130 */
//
// Generated on: 2026-02-01 05:02:10.474466367 +0000 UTC m=+0.220993316

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

var Authorities = []DirectoryAuthority{
	{
		Nickname:    "moria1",
		ORPort:      9201,
		IPv4:        "128.31.0.39",
		DirPort:     9231,
		V3Ident:     "F533C81CEF0BC0267857C99B2F471ADF249FA232 ",
		Fingerprint: "1A25C6358DB91342AA51720A5038B72742732498",
	},
	{
		Nickname:    "tor26",
		ORPort:      443,
		IPv4:        "217.196.147.77",
		DirPort:     80,
		IPv6:        "2a02:16a8:662:2203::1",
		IPv6Port:    0,
		V3Ident:     "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C ",
		Fingerprint: "FAA4BCA4A6AC0FB4CA2F8AD5A11D9E122BA894F6",
	},
	{
		Nickname:    "dizum",
		ORPort:      443,
		IPv4:        "45.66.35.11",
		DirPort:     80,
		V3Ident:     "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 ",
		Fingerprint: "7EA6EAD6FD83083C538F44038BBFA077587DD755",
	},
	{
		Nickname:    "Serge",
		ORPort:      9001,
		IPv4:        "66.111.2.131",
		DirPort:     9030,
		Fingerprint: "BA44A889E64B93FAA2B114E02C2A279A8555C533",
		IsBridge:    true,
	},
	{
		Nickname:    "gabelmoo",
		ORPort:      443,
		IPv4:        "131.188.40.189",
		DirPort:     80,
		IPv6:        "2001:638:a000:4140::ffff:189",
		IPv6Port:    0,
		V3Ident:     "ED03BB616EB2F60BEC80151114BB25CEF515B226 ",
		Fingerprint: "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281",
	},
	{
		Nickname:    "dannenberg",
		ORPort:      443,
		IPv4:        "193.23.244.244",
		DirPort:     80,
		IPv6:        "2001:678:558:1000::244",
		IPv6Port:    0,
		V3Ident:     "0232AF901C31A04EE9848595AF9BB7620D4C5B2E ",
		Fingerprint: "7BE683E65D48141321C5ED92F075C55364AC7123",
	},
	{
		Nickname:    "maatuska",
		ORPort:      80,
		IPv4:        "171.25.193.9",
		DirPort:     443,
		IPv6:        "2001:67c:289c::9",
		IPv6Port:    0,
		V3Ident:     "49015F787433103580E3B66A1707A00E60F2D15B ",
		Fingerprint: "BD6A829255CB08E66FBE7D3748363586E46B3810",
	},
	{
		Nickname:    "longclaw",
		ORPort:      443,
		IPv4:        "199.58.81.140",
		DirPort:     80,
		V3Ident:     "23D15D965BC35114467363C165C4F724B64B4F66 ",
		Fingerprint: "74A910646BCEEFBCD2E874FC1DC997430F968145",
	},
	{
		Nickname:    "bastet",
		ORPort:      443,
		IPv4:        "204.13.164.118",
		DirPort:     80,
		IPv6:        "2620:13:4000:6000::1000:118",
		IPv6Port:    0,
		V3Ident:     "27102BC123E7AF1D4741AE047E160C91ADC76B21 ",
		Fingerprint: "24E2F139121D4394C54B5BCC368B3B411857C413",
	},
	{
		Nickname:    "faravahar",
		ORPort:      443,
		IPv4:        "216.218.219.41",
		DirPort:     80,
		V3Ident:     "70849B868D606BAECFB6128C5E3D782029AA394F ",
		Fingerprint: "E3E42D35F801C9D5AB23584E0025D56FE2B33396",
	},
}
