package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
	runar.SmartContract
	Target runar.Int `runar:"readonly"`
}

func (c *Arithmetic) Verify(a runar.Int, b runar.Int) {
	sum := a + b
	diff := a - b
	prod := a * b
	quot := a / b
	result := sum + diff + prod + quot
	runar.Assert(result == c.Target)
}
