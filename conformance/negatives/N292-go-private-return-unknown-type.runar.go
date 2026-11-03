// N-331: a Go-surface private method whose return type names a type that does
// not exist. Before the fix every tier accepted it.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type PrivateReturnUnknownType struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *PrivateReturnUnknownType) helper(x runar.Int) runar.TTT {
	return 1
}

func (c *PrivateReturnUnknownType) Verify(a runar.Int) {
	runar.Assert(a == c.T)
}
