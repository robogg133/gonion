package common

import "crypto/ed25519"

type Microdesc struct {
	OnionKey     []byte
	NTorOnionKey []byte            // curve25519
	IdEd25519    ed25519.PublicKey // ed25519
	Family       []Family
	Familys      []*FamilyIDs

	ExitRules *Ports
}

type Family struct {
	Digest   []byte
	Nickname string
}

type FamilyIDs struct {
	Kind  string
	Value []byte
}