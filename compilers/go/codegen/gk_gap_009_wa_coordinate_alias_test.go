package codegen_test

// GK-GAP-009 (witness-assisted Groth16 path): the preamble reads proof.A,
// proof.B, proof.C and prepared_inputs as raw script numbers from the
// unlocking script. Before the fix, the G1 check only bounded x, y from above
// (OP_LESSTHAN p) and the G2 check bounded nothing, while every later use is
// arithmetic mod p. A spender (or any third party relaying the spend) could
// therefore swap a coordinate for another integer congruent to it mod p and
// the verifier still accepted: same proof, different unlocking script bytes,
// different txid.
//
// Setup: the real SP1 v6.0.0 VK + proof (tests/vectors/sp1/v6.0.0) through
// EmitGroth16VerifierWitnessAssistedWithMSM, honest witness from
// bn254witness.BuildFromProofWithInputs, then exactly one coordinate replaced
// by coordinate ± p. Every gradient stays the honest one (it is computed for
// the canonical point, which the aliased encoding is congruent to).
//
// Proves: the verifier aborts on each aliased encoding below and still
// accepts the unmodified honest witness.
// Does not prove: anything about the gradient or residue witnesses, which are
// not range-checked (see the GK-GAP-009 notes in the remediation report).

import (
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

func TestGKGAP009_WAVerifierRejectsAliasedCoordinates(t *testing.T) {
	if testing.Short() {
		t.Skip("minutes-long interpreter runs")
	}
	vk, proof, pubs := gk005LoadSP1(t)
	verifier := gk005Verifier(true, gk005MSMConfig(t, vk))
	p := codegen.Bn254FieldPrime()
	plusP := func(v *big.Int) *big.Int { return new(big.Int).Add(v, p) }
	minusP := func(v *big.Int) *big.Int { return new(big.Int).Sub(v, p) }

	t.Run("Control_HonestProofAccepted", func(t *testing.T) {
		if err := gk005Run(verifier, gk005Witness(t, true, vk, proof, pubs)); err != nil {
			t.Fatalf("honest SP1 proof rejected: %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(w *bn254witness.Witness)
	}{
		// G2 limbs: no range check at all before the fix.
		{"proof_bx0_plus_p", func(w *bn254witness.Witness) { w.ProofB[0] = plusP(w.ProofB[0]) }},
		{"proof_by1_minus_p", func(w *bn254witness.Witness) { w.ProofB[3] = minusP(w.ProofB[3]) }},
		// G1 y: only an upper bound before the fix; y - p is negative.
		{"pi_y_minus_p", func(w *bn254witness.Witness) { w.PreparedInputs[1] = minusP(w.PreparedInputs[1]) }},
		{"proof_ay_minus_p", func(w *bn254witness.Witness) { w.ProofA[1] = minusP(w.ProofA[1]) }},
		// G1 x: x - p is negative too; kept as a regression guard.
		{"pi_x_minus_p", func(w *bn254witness.Witness) { w.PreparedInputs[0] = minusP(w.PreparedInputs[0]) }},
		{"proof_ax_minus_p", func(w *bn254witness.Witness) { w.ProofA[0] = minusP(w.ProofA[0]) }},
	} {
		tc := tc
		t.Run("AliasRejected_"+tc.name, func(t *testing.T) {
			w := gk005Witness(t, true, vk, proof, pubs)
			tc.mutate(w)
			if err := gk005Run(verifier, w); err == nil {
				t.Fatalf("GK-GAP-009: verifier ACCEPTED the honest proof with %s (alternate encoding of the same point)", tc.name)
			} else {
				t.Logf("aliased encoding rejected: %v", err)
			}
		})
	}
}
