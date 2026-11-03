// N-153: a valid Go block statement. Rúnar has no block statement on the .go
// surface (nor on .sol / .move / .rs). Pre-fix every tier refused this, but
// for unrelated reasons (an unexpected `:=` inside a brace literal, ...). Every
// tier must refuse it; the TS reference says:
//   Unexpected token in expression: '{'
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type N192 struct {
	runar.SmartContract
	T runar.Bigint `runar:"readonly"`
}

func (c *N192) Unlock(x runar.Bigint) {
	{
		y := x
		runar.Assert(y == c.T)
	}
}
