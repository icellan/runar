//go:build ignore

// N-056 (R51): `a << b * d` groups as `(a << b) * d` under Go precedence (go/parser,
// the Go tier) and as `a << (b * d)` under the C ladder every other tier and
// surface uses. Pre-fix the same source compiled to two different scripts.
// Every tier must refuse it with:
//   ambiguous operator precedence in .runar.go: `a << b * c` groups differently
//   under Go precedence than in Rúnar's other surfaces; add parentheses
// Both parenthesised spellings compile (go-precedence-control.runar.go).
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type PrecShiftMul struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *PrecShiftMul) Unlock(a runar.Int, b runar.Int, d runar.Int) {
	runar.Assert((a << b * d) == c.T)
}
