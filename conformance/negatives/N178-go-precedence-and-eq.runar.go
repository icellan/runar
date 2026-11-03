//go:build ignore

// N-056 (R51): `a & 255 == 15` groups as `(a & 255) == 15` under Go precedence (go/parser,
// the Go tier) and as `a & (255 == 15)` under the C ladder every other tier and
// surface uses. Pre-fix the Go tier compiled it and the six C-ladder tiers
// refused it in the typechecker (bigint & bool) — the idiomatic Go mask test
// was a one-tier program.
// Every tier must refuse it with:
//   ambiguous operator precedence in .runar.go: `a & b == c` groups differently
//   under Go precedence than in Rúnar's other surfaces; add parentheses
// `(a & 255) == 15` compiles (go-precedence-control.runar.go).
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type PrecAndEq struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *PrecAndEq) Unlock(a runar.Int, b runar.Int, d runar.Int) {
	runar.Assert(a & 255 == 15)
}
