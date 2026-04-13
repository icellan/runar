package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupGroth16WA — minimal stateful contract that embeds the witness-assisted
// BN254 Groth16 verifier as a method-entry preamble.
//
// The verifier is inlined at compile time when the contract is compiled with
// CompileOptions.Groth16WAVKey set to a SP1-format Groth16 vk.json file. The
// VK values are baked into the locking script. At spend time, the SDK helper
// pushes the witness-assisted prover bundle (gradients, final-exp witnesses,
// MSM points, proof points) on TOP of the regular ABI argument pushes; the
// verifier preamble consumes them before the method body sees its arguments.
//
// This contract is the failing-test target for the Mode 3 deliverable. Until
// the AssertGroth16WitnessAssisted primitive and its codegen wiring exist,
// compilation will fail at the type-check pass with "unknown function".
type RollupGroth16WA struct {
	runar.StatefulSmartContract

	// Mutable state — minimal state shape that exercises the variable-length
	// state path through deserialize_state (32-byte ByteString + Bigint).
	StateRoot   runar.ByteString
	BlockNumber runar.Bigint
}

// AdvanceState verifies a witness-assisted Groth16 proof and updates the
// state root. The verifier preamble is inlined at the very start of the
// method (before any of the regular ABI args are bound), so when the body
// proper begins, the witness items have already been consumed and the
// stack contains only the declared parameters.
//
// The deliberate design constraint: AssertGroth16WitnessAssisted MUST be
// the first statement of the method. The codegen recognises it as a marker
// for the preamble; placing it later in the body would not be valid because
// the witness items only exist on top of the stack at method entry.
func (c *RollupGroth16WA) AdvanceState(newStateRoot runar.ByteString, newBlockNumber runar.Bigint) {
	runar.AssertGroth16WitnessAssisted()

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
}
