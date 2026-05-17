package x

import runar "github.com/icellan/runar/packages/runar-go"

// IntentCurrentBlockHeight exercises the runar.CurrentBlockHeight
// shorthand, which is pure source-level sugar for
// `runar.ExtractLocktime(this.txPreimage)`. The desugar happens at ANF
// lowering time — no new ANF kind or stack codegen is needed.
type IntentCurrentBlockHeight struct {
	runar.StatefulSmartContract

	Deadline runar.Bigint `runar:"readonly"`
	Count    runar.Bigint
}

func (c *IntentCurrentBlockHeight) Spend() {
	h := runar.CurrentBlockHeight()
	runar.Assert(h <= c.Deadline)
	c.Count = c.Count + 1
}
