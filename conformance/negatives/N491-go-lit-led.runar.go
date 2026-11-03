// N-491: TS surface-parser operand anchor parity. A bigint composite whose first token is a literal, as the left operand of `&&`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Anchor struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *Anchor) Go(x runar.Int, flag runar.Bool) {
	runar.Assert(5 + 1 && flag)
}
