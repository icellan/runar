package x

import runar "github.com/icellan/runar/packages/runar-go"

// IntentPrevOutputScript exercises the runar.ExtractPrevOutputScript
// intrinsic.
//
// It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
// caller-supplied byte string hashes to `expectedHash` and returns it; this
// contract then asserts the string is non-empty. The first argument is a
// compile-time label naming the auto-injected witness parameter
// `_prevOutScript_0`, which the unlocking script supplies. There is no vin
// lookup, no parent transaction and no input-count check in the emitted
// script. For a construction that binds a specific companion INPUT, see
// `examples/ts/companion-verifier/`.
type IntentPrevOutputScript struct {
	runar.StatefulSmartContract

	ExpectedHash runar.ByteString `runar:"readonly"`
	Count        runar.Bigint
}

func (c *IntentPrevOutputScript) Bind() {
	s := runar.ExtractPrevOutputScript(0, c.ExpectedHash)
	runar.Assert(runar.Len(s) > 0)
	c.Count = c.Count + 1
}
