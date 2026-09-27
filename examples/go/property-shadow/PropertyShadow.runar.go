package contract

import runar "github.com/icellan/runar/packages/runar-go"

// PropertyShadow — N-016 conformance fixture. The locals are spelled exactly
// like the fields (`Target`, `Count`) so they convert to the same Rúnar name
// without tripping the F-017 two-spellings rule; `c.Target` / `c.Count` must
// still read the fields.
type PropertyShadow struct {
	runar.StatefulSmartContract
	Target runar.Int `runar:"readonly"`
	Count  runar.Int
}

func (c *PropertyShadow) Bump(n runar.Int) {
	Target := n + 1
	runar.Assert(Target == c.Target)
	Count := n
	c.Count = c.Count + Count
	runar.Assert(c.Count > Count)
}
