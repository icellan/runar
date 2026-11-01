// N-491: TS surface-parser operand anchor parity. A bigint identifier as the right operand of `&&`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Anchor struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *Anchor) Go(x runar.Int, flag runar.Bool) {
	runar.Assert(flag && x)
}
