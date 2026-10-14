package contract

import runar "github.com/icellan/runar/packages/runar-go"

// EmbedTags is the Go port of
// examples/ts/compiler-directives/EmbedTags.runar.ts.
//
// The embedAlways struct tag option on a fixed-array field applies to every
// expanded slot: all three are kept although Unlock reads only Tags[1]. The
// array literal lives in the private init() method, which is how the Go DSL
// spells a property initializer.
type EmbedTags struct {
	runar.SmartContract
	PubKeyHash runar.Addr   `runar:"readonly"`
	Tags       [3]runar.Int `runar:"readonly,embedAlways"`
}

func (c *EmbedTags) init() {
	c.Tags = [3]runar.Int{7, 9, 11}
}

func (c *EmbedTags) Unlock(sig runar.Sig, pubKey runar.PubKey, amount runar.Int) {
	runar.Assert(amount >= c.Tags[1])
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
