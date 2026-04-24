package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// Sp1FriVerifierPoc exercises the `runar.VerifySP1FRI` intrinsic at the
// frontend level so covenant authors can write ABIs against it before the
// STARK verifier codegen body lands.
//
// The intrinsic takes three ByteString inputs:
//
//   - proofBlob     — bincode-encoded Plonky3 FriProof (see docs/sp1-proof-format.md)
//   - publicValues  — guest-program public-values blob absorbed into the transcript
//   - sp1VKeyHash   — 32-byte keccak256 digest of the SP1 verifying key (readonly)
//
// Semantics: returns true on a valid proof. On an invalid proof the
// compiled script fails OP_VERIFY at the first detectable mismatch. See
// docs/sp1-fri-verifier.md for the transcript order, performance targets,
// fallback order, and negative-test corruption matrix.
//
// # Status
//
// The type-checker and ANF lowering accept the call so BSVM's covenant
// (pkg/covenant/contracts/rollup_fri.runar.go in the bsv-evm repo) can be
// written against this ABI. Stack lowering is deferred — any attempt to
// compile past ANF raises "verifySP1FRI codegen body not yet implemented".
// See docs/sp1-fri-verifier.md §8.
type Sp1FriVerifierPoc struct {
	runar.SmartContract
	// Sp1VKeyHash is the 32-byte keccak256 digest of the SP1 verifying key.
	// Bound at compile time; a malicious unlocking script cannot supply it.
	Sp1VKeyHash runar.ByteString `runar:"readonly"`
}

// Verify checks an SP1 v6.0.2 STARK / FRI proof on-chain.
//
// On a valid proof the script returns without residue. On an invalid proof
// the script fails OP_VERIFY.
func (v *Sp1FriVerifierPoc) Verify(
	proofBlob runar.ByteString,
	publicValues runar.ByteString,
) {
	runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, v.Sp1VKeyHash))
}
