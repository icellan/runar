// N-065: the Go surface maps the exported field `T1` to the property `t1`, an ANF
// temp name. Every tier must refuse with:
//   't1' is reserved for compiler-generated names and cannot be used as an identifier
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type RGoPropertyT1MapsToT1 struct {
	runar.SmartContract
	T1 runar.Int `runar:"readonly"`
}

func (c *RGoPropertyT1MapsToT1) Verify(a runar.Int) {
	runar.Assert(a == c.T1)
}
