package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// StatelessGroth16WA is the simplest possible stateless contract that
// embeds the witness-assisted Groth16 verifier as a method preamble.
// It has no state fields and no continuation logic — one readonly
// constructor arg and a single Verify() method.
//
// The preamble is the MSM-binding verifier
// (AssertGroth16WitnessAssistedWithMSM), which recomputes prepared_inputs
// from the five public-input scalars on-chain. The body then fixes the
// statement: public input 0 (the SP1 program verifying-key hash) must be
// ProgramVKeyHash, so a proof for any other program cannot spend. The raw
// AssertGroth16WitnessAssisted this contract used to call never saw the
// public inputs at all and is a compile error since GK-BUG-006.
//
// Used to isolate Mode 3 preamble bugs from anything in the stateful
// continuation path.
type StatelessGroth16WA struct {
	runar.SmartContract

	ProgramVKeyHash runar.Bigint `runar:"readonly"`
}

func (c *StatelessGroth16WA) Verify() {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(0) == c.ProgramVKeyHash)
}
