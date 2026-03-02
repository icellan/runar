package contract

import "runar"

type Stateful struct {
	runar.StatefulSmartContract
	Count    runar.Int
	MaxCount runar.Int `runar:"readonly"`
}

func (c *Stateful) Increment(amount runar.Int, txPreimage runar.SigHashPreimage) {
	runar.Assert(runar.CheckPreimage(txPreimage))
	c.Count = c.Count + amount
	runar.Assert(c.Count <= c.MaxCount)
	runar.Assert(runar.Hash256(c.GetStateScript()) == runar.ExtractOutputHash(txPreimage))
}

func (c *Stateful) Reset(txPreimage runar.SigHashPreimage) {
	runar.Assert(runar.CheckPreimage(txPreimage))
	c.Count = 0
	runar.Assert(runar.Hash256(c.GetStateScript()) == runar.ExtractOutputHash(txPreimage))
}
