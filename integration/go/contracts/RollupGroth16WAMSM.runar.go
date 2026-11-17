package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupGroth16WAMSM — stateful contract that embeds the MSM-binding
// witness-assisted BN254 Groth16 verifier preamble and fixes the proved
// statement in its method body.
//
// The preamble recomputes the SP1 public-inputs multi-scalar multiplication
// on-chain and asserts it matches the prover-supplied prepared_inputs, so the
// five witness scalars are bound to the proof. On their own they are still
// the PROVER's choice: the body pins public input 0, the SP1 program
// verifying-key hash, to ProgramVKeyHash (a readonly constructor arg), so a
// proof of some other program cannot advance the state. RollupGroth16WA does
// the same through vk.json pinnedPublicInputs instead.
//
// A real rollup must also tie the committed-values digest (pub_1) to the
// state transition; this contract only exercises the Mode 3 wiring.
type RollupGroth16WAMSM struct {
	runar.StatefulSmartContract

	// ProgramVKeyHash is the SP1 program verifying-key hash (public input
	// 0) every accepted proof must be about.
	ProgramVKeyHash runar.Bigint `runar:"readonly"`

	// StateRoot and BlockNumber mirror the RollupGroth16WA shape so the
	// same deployment / advance flow is exercised.
	StateRoot   runar.ByteString
	BlockNumber runar.Bigint
}

// AdvanceState verifies a witness-assisted + MSM-binding Groth16 proof
// and updates the state root.
//
// AssertGroth16WitnessAssistedWithMSM MUST be the first statement so the
// codegen recognises the method as needing the MSM-binding preamble.
func (c *RollupGroth16WAMSM) AdvanceState(newStateRoot runar.ByteString, newBlockNumber runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(0) == c.ProgramVKeyHash)

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
}
