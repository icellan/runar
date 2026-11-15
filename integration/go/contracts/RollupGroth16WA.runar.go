package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupGroth16WA — minimal stateful contract that embeds the MSM-binding
// witness-assisted BN254 Groth16 verifier as a method-entry preamble, with
// the statement fixed by the VERIFYING KEY it is compiled with rather than by
// the method body.
//
// The verifier is inlined at compile time when the contract is compiled with
// CompileOptions.Groth16WAVKey set to a SP1-format Groth16 vk.json file. The
// VK values are baked into the locking script. At spend time, the SDK helper
// pushes the witness-assisted prover bundle (gradients, residue witness,
// public inputs, prepared inputs, proof points) on TOP of the regular ABI
// argument pushes; the verifier preamble consumes them before the method body
// sees its arguments.
//
// Statement binding: the vk.json MUST pin the SP1 program verifying-key hash
// (pub_0), the exit code (pub_2) and the vk root (pub_3) with
// "pinnedPublicInputs" (see groth16_wa_stateful_test.go). The MSM preamble
// then requires the witness scalars to equal the pins. Compiled with an
// unpinned vk.json, nothing would tie the proof to a program;
// RollupGroth16WAMSM shows the in-body alternative. (This contract used to
// call the raw AssertGroth16WitnessAssisted, which never saw the public
// inputs; that marker is a compile error since GK-BUG-006.)
//
// A real rollup must also tie the committed-values digest (pub_1) to the
// state transition; this contract only exercises the Mode 3 wiring.
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
// stack contains only the declared parameters (plus the five public-input
// scalars the MSM preamble leaves for groth16PublicInput).
//
// The deliberate design constraint: AssertGroth16WitnessAssistedWithMSM
// MUST be the first statement of the method. The codegen recognises it as a
// marker for the preamble; placing it later in the body would not be valid
// because the witness items only exist on top of the stack at method entry.
func (c *RollupGroth16WA) AdvanceState(newStateRoot runar.ByteString, newBlockNumber runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
}
