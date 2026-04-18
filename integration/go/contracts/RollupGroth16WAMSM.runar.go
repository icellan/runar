package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupGroth16WAMSM — stateful contract that embeds the MSM-binding
// witness-assisted BN254 Groth16 verifier preamble. Unlike the sibling
// RollupGroth16WA (which uses the raw AssertGroth16WitnessAssisted), this
// variant also recomputes the SP1 public-inputs multi-scalar multiplication
// on-chain and asserts it matches the prover-supplied prepared_inputs.
//
// The soundness upgrade: a hostile prover that bypasses the Rúnar SDK
// cannot supply an arbitrary prepared_inputs point paired with a bespoke
// proof — the on-chain MSM derived from config.IC (baked at compile time)
// and the 5 witness-pushed pub_i scalars must agree with the point the
// pairing consumes.
type RollupGroth16WAMSM struct {
	runar.StatefulSmartContract

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

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
}
