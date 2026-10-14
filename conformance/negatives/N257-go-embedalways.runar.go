package contract

import runar "github.com/icellan/runar/packages/runar-go"

// N-268: an `embedAlways` marker on a readonly field on the Go DSL surface.
// Only .runar.ts honours the directive; every other surface must refuse it
// with the one shared "not supported by the Go DSL surface parser" message
// (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
// each used their own, differently worded text here).
// With the marker replaced by prose, MetadataId is an ordinary unreferenced
// readonly field: every tier eliminates it by DCE, so this compiles to the
// same P2PKH-shaped script everywhere.
type Meta struct {
	runar.SmartContract
	PubKeyHash runar.Addr `runar:"readonly"`
	// @embedAlways
	MetadataId runar.ByteString `runar:"readonly"`
}

func (c *Meta) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
