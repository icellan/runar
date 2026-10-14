// N-244: the sighash marker glued to its flag list on the Go DSL surface.
// Only .runar.ts honours the directive; every other surface must refuse ANY
// occurrence of the marker (N-039's rule), not just a word-bounded one, with
// the one shared "not supported by the Go DSL surface parser" message.
// Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

// @sighashSINGLE|FORKID
func (c *Counter) Increment() {
	c.Count++
}
