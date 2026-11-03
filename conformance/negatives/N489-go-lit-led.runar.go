// N-489: typecheck diagnostic anchor parity. A bigint composite whose first token is a literal, as the left operand of `&&`.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Anchor struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *Anchor) Go(x runar.Int, flag runar.Bool) {
	runar.Assert(5 + 1 && flag)
}
