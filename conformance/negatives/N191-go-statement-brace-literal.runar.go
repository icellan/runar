// N-153: a .runar.go `{` at statement start. The TS reference, Rust, Python,
// Ruby and Java read it as a brace composite literal, so they ACCEPTED
// `{ x, c.check(x) }`, which is not Go at all; Go (go/parser) and Zig refused.
// Every tier must refuse a statement that starts with `{`; the TS reference
// says:
//   Unexpected token in expression: '{'
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type N191 struct {
	runar.SmartContract
	T runar.Bigint `runar:"readonly"`
}

func (c *N191) Unlock(x runar.Bigint) {
	{ x, c.check(x) }
	runar.Assert(true)
}

func (c *N191) check(x runar.Bigint) runar.Bigint {
	runar.Assert(x == c.T)
	return x
}
