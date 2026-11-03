package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ParamShadowBranchArm — N-007 conformance fixture. The parameter is spelled
// exactly like the field (`Count`) so both convert to the same Rúnar name
// without tripping the F-017 two-spellings rule; inside the `if` arm `Count`
// is still the parameter, and `c.Count` is the field.
type ParamShadowBranchArm struct {
	runar.StatefulSmartContract
	Count runar.Int
}

func (c *ParamShadowBranchArm) Set(Count runar.Int, flag runar.Bool) {
	if flag {
		runar.Assert(Count == 5)
	}
	c.Count = Count
}
