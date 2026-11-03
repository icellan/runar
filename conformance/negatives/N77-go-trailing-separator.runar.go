// F-026: in Go "_ must separate successive digits", so `10_` is not a Go
// integer literal. Pre-fix six tiers read it as 10 and only the Go tier
// (go/parser) refused it. Every tier must refuse; the hand-written tokenizers
// say:
//   invalid Go integer literal '10_'
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type T struct {
	runar.SmartContract
	Target runar.Int `runar:"readonly"`
}

func (c *T) Verify(a runar.Int) {
	runar.Assert(a > 10_)
}
