package x

import runar "github.com/icellan/runar/packages/runar-go"

// IntentPrevOutputScript exercises the runar.ExtractPrevOutputScript
// intrinsic. The contract reads input 0's previous-output locking script
// via the witness-bridge pattern and asserts it is non-empty after the
// hash-equality check the intrinsic emits internally.
//
// The auto-injected method parameter `_prevOutScript_0` is supplied by
// the unlocking script and verified against `expectedHash` inside the
// intrinsic.
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
