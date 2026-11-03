package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// THIS CONTRACT DOES NOT COMPILE IN V1 (F-007).
//
// The SP1 FRI verifier is not implemented for v1: the emitted body checks only
// the Fiat-Shamir transcript and grinding witnesses, never the per-query MMCS
// openings, FRI fold chain, final-poly equality or Steps 6/7 out-of-domain
// constraint check. The body is therefore fail-closed (it can never accept) and
// the compiler refuses every contract that calls verifySP1FRI, with no
// override. This file is kept as the ABI reference and test input for that
// refusal and for the post-v1 verifier. See docs/sp1-fri-verifier.md.
//
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
// Refused at compile time in v1 (F-007); see the header above.
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
