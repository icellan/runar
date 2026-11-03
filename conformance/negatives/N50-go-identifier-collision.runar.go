//go:build ignore

// F-017 — a Go local whose name converts to a FIELD's Rúnar name.
//
// The .runar.go surface lowers the first letter of an exported name, so the
// field `K` becomes `k` — the same name as the local `k`. Go keeps them
// distinct (`k` is n + 1, `c.K` is the property), but both land on one
// Rúnar name.
//
// Every tier must refuse with:
//   identifier collision: 'K' and 'k' both convert to 'k'; rename one of them
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type IdentCollisionGo struct {
	runar.SmartContract
	K runar.Int `runar:"readonly"`
}

func (c *IdentCollisionGo) Unlock(n runar.Int) {
	k := n + 1
	runar.Assert(k == c.K)
}
