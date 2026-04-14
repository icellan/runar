package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// StatelessGroth16WA is the simplest possible stateless contract that
// embeds the witness-assisted Groth16 verifier as a method preamble.
// It has no state fields, no constructor args, no continuation logic —
// just a single Verify() method that calls AssertGroth16WitnessAssisted.
//
// Used to isolate Mode 3 preamble bugs from anything in the stateful
// continuation path.
type StatelessGroth16WA struct {
	runar.SmartContract
}

func (c *StatelessGroth16WA) Verify() {
	runar.AssertGroth16WitnessAssisted()
	runar.Assert(true)
}
