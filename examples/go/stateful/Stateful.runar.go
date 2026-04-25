//go:build ignore

package contract

import "runar"

type Stateful struct {
	runar.StatefulSmartContract
	Count    runar.Int
	MaxCount runar.Int `runar:"readonly"`
}

func (c *Stateful) Increment(amount runar.Int) {
	c.Count = c.Count + amount
	runar.Assert(c.Count <= c.MaxCount)
}

func (c *Stateful) Reset() {
	c.Count = 0
}
