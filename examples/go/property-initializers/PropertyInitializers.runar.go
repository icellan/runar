//go:build ignore

package contract

import "runar"

type PropertyInitializers struct {
	runar.StatefulSmartContract
	Count    runar.Int
	MaxCount runar.Int `runar:"readonly"`
	Active   runar.Bool `runar:"readonly"`
}

func (c *PropertyInitializers) init() {
	c.Count = 0
	c.Active = true
}

func (c *PropertyInitializers) Increment(amount runar.Int) {
	runar.Assert(c.Active)
	c.Count = c.Count + amount
	runar.Assert(c.Count <= c.MaxCount)
}

func (c *PropertyInitializers) Reset() {
	c.Count = 0
}
