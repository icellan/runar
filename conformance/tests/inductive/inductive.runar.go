package contract

import "runar"

type Inductive struct {
	runar.InductiveSmartContract
	Count    runar.Int
	MaxCount runar.Int `runar:"readonly"`
}

func (c *Inductive) Increment(amount runar.Int) {
	c.Count = c.Count + amount
	runar.Assert(c.Count <= c.MaxCount)
}

func (c *Inductive) Reset() {
	c.Count = 0
}
