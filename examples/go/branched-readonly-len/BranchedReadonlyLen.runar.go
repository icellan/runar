package x

import runar "github.com/icellan/runar/packages/runar-go"

// BranchedReadonlyLen exercises a state-mutating if/else branched on a
// read-only intrinsic value (`runar.Len`). The hand-off §3 affine-checker
// concern: branching on a `bigint`-returning intrinsic with state
// mutations on both arms must pass the affine type checker. If this
// contract compiles cleanly across all 7 tiers, the AdvanceState fold-in
// (BSVM-side) is unblocked.
type BranchedReadonlyLen struct {
	runar.StatefulSmartContract

	Count runar.Bigint
	Tag   runar.ByteString
}

func (c *BranchedReadonlyLen) Spend(scratch runar.ByteString) {
	if runar.Len(scratch) > 0 {
		c.Count = c.Count + 1
		c.Tag = scratch
	} else {
		c.Count = c.Count - 1
		c.Tag = runar.ByteString("00")
	}
	c.AddOutput(1000, c.Count, c.Tag)
}
