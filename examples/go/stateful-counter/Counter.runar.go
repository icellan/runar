package contract

import "runar"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint // no tag = mutable (stateful)
}

func (c *Counter) Increment() {
	c.Count++
}

func (c *Counter) Decrement() {
	runar.Assert(c.Count > 0)
	c.Count--
}
