package compiler

// GK-BUG-005 on the bytes that are actually deployed: the CompileGroth16WA
// artifact for the SP1 v6.0.0 VK (peephole-optimised, opened by the owner's
// <ownerPubKey> OP_CHECKSIGVERIFY, public inputs pinned to the fixture's),
// spent with a real owner signature through executeArtifactWithWitness.
//
// codegen's TestGKBUG005_* run the full forgery set against the emitter ops
// (raw, WithMSM, and WithMSM after the same peephole passes). This file
// checks the residue witness end to end on the production artifact, with a
// false statement the pins cannot catch: the fixture's own public inputs and
// a proof whose A is replaced by the G1 generator. Its Miller gradients,
// subgroup gradients and MSM are all honest for that proof, so only the
// residue check (f·ω^s == c^λ) stands between it and acceptance.
//
// Proves: the deployed verifier accepts the honest SP1 proof and rejects the
// generator's witness for a false statement, a wrong in-range scaling index,
// a scaling index outside {0, 1, 2}, and a c⁻¹ that is not c's inverse.
// Does not prove: the forgeries that need off-chain construction (the
// independent c/c⁻¹ pair, root-formula c under every s) — those run on the
// optimised ops in codegen's TestGKBUG005_WithMSMOptimized.

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

func gk005FinalExpIsOne(flat [12]*big.Int) bool {
	var z bn254.E12
	for i, c := range []*bn254.E2{&z.C0.B0, &z.C0.B1, &z.C0.B2, &z.C1.B0, &z.C1.B1, &z.C1.B2} {
		c.A0.SetBigInt(flat[2*i])
		c.A1.SetBigInt(flat[2*i+1])
	}
	fin := bn254.FinalExponentiation(&z)
	return fin.IsOne()
}

func TestGKBUG005_CompiledArtifact_ResidueWitness(t *testing.T) {
	if testing.Short() {
		t.Skip("executes the ~1.5 MB SP1 verifier on the go-sdk interpreter")
	}
	pubs := sp1PublicInputs(t)
	art, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{PublicInputs: pubs})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}
	vk, err := bn254witness.LoadSP1VKFromFile(sp1VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}
	proof := sp1RawProof(t)

	mustReject := func(t *testing.T, w *bn254witness.Witness, what string) {
		t.Helper()
		if err := executeArtifactWithWitness(t, art, w); err == nil {
			t.Fatalf("GK-BUG-005: the deployed CompileGroth16WA verifier ACCEPTED %s", what)
		} else {
			t.Logf("rejected: %v", err)
		}
	}

	t.Run("Control_HonestWitnessAccepted", func(t *testing.T) {
		if err := executeArtifactWithWitness(t, art, sp1Witness(t, pubs)); err != nil {
			t.Fatalf("honest SP1 v6 proof rejected by the deployed verifier: %v", err)
		}
	})

	t.Run("FalseStatement_GeneratorWitnessRejected", func(t *testing.T) {
		bad := proof
		bad.A = [2]*big.Int{big.NewInt(1), big.NewInt(2)}
		f, err := bn254witness.MillerLoopProduct(vk, bad, pubs)
		if err != nil {
			t.Fatalf("MillerLoopProduct: %v", err)
		}
		if gk005FinalExpIsOne(f) {
			t.Fatal("premise broken: the tampered proof verifies off-chain")
		}
		w, err := bn254witness.BuildFromProofWithInputs(vk, bad, pubs)
		if err != nil {
			t.Fatalf("BuildFromProofWithInputs: %v", err)
		}
		mustReject(t, w, "the generator's residue witness for a false statement (proof.A = G1)")
	})

	t.Run("WrongScalingIndexRejected", func(t *testing.T) {
		w := sp1Witness(t, pubs)
		w.ResidueScaling = (w.ResidueScaling + 1) % 3
		mustReject(t, w, "the honest c with a wrong in-range scaling index")
	})

	t.Run("ScalingIndexOutsideSetRejected", func(t *testing.T) {
		w := sp1Witness(t, pubs)
		w.ResidueScaling = 3
		mustReject(t, w, "scaling index 3")
	})

	t.Run("CInvNotInverseRejected", func(t *testing.T) {
		w := sp1Witness(t, pubs)
		w.ResidueCInv[0] = new(big.Int).Add(w.ResidueCInv[0], big.NewInt(1))
		mustReject(t, w, "a c⁻¹ that is not the inverse of c")
	})
}
