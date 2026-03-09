package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BoundedCounter demonstrates property initializers in Go format.
//
// Properties assigned in the init() method are excluded from the auto-generated
// constructor. Only MaxCount needs to be provided at deploy time.
type BoundedCounter struct {
	runar.StatefulSmartContract
	Count    runar.Bigint
	MaxCount runar.Bigint `runar:"readonly"`
	Active   runar.Bool   `runar:"readonly"`
}

func (c *BoundedCounter) init() {
	c.Count = 0
	c.Active = true
}

func (c *BoundedCounter) Increment(amount runar.Bigint) {
	runar.Assert(c.Active)
	c.Count = c.Count + amount
	runar.Assert(c.Count <= c.MaxCount)
}

func (c *BoundedCounter) Reset() {
	c.Count = 0
}
