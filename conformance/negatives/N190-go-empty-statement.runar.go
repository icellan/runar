// N-153: a .runar.go empty statement `;`. The TS reference and the Go tier
// (go/parser EmptyStmt) refuse it; the Rust, Python and Java tiers skipped it.
// Every tier must refuse it; the TS reference says:
//   Unexpected token in expression: ';'
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type N190 struct {
	runar.SmartContract
	T runar.Bigint `runar:"readonly"`
}

func (c *N190) Unlock(x runar.Bigint) {
	runar.Assert(x == c.T)
	;
}
