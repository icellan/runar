package contract

import runar "github.com/icellan/runar/packages/runar-go"

// SingleCounter is the Go port of
// examples/ts/sighash-single-stateful/SingleCounter.runar.ts.
//
// Bump carries the directive comment //runar:sighash SINGLE|FORKID (N-093), so
// its auto-injected continuation commits only the output at its own index: no
// change segment and no _changePKH / _changeAmount parameter (N-038). SINGLE
// does not pin the continuation's value, so Bump re-creates it at the full
// input amount read from the preimage. Reset keeps ALL|FORKID.
type SingleCounter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

//runar:sighash SINGLE|FORKID
func (c *SingleCounter) Bump() {
	c.AddOutput(runar.ExtractAmount(c.TxPreimage), c.Count+1)
}

func (c *SingleCounter) Reset() {
	runar.Assert(c.Count > 0)
	c.Count = 0
}
