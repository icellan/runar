package codegen

import (
	"math/big"
	"testing"
)

// TestBN254_FrobeniusCoefficients verifies the Frobenius endomorphism
// coefficients defined in bn254_ext.go init(). These are the γ_{1,*} (Fp2)
// and γ_{2,*} (Fp) constants used by bn254Fp12FrobeniusP and FrobeniusP2.
//
// This file checks static algebraic identities only (range, non-zero,
// p-1 equalities, pairwise differences). For behavioral cross-validation
// against gnark-crypto's reference implementation on real Fp12 values, see:
//   - packages/runar-go/bn254witness/witness_test.go
//     TestEmitFp12FrobeniusP_ScriptMatchesGnark
//     TestEmitFp12FrobeniusP2_ScriptMatchesGnark
// Those tests run the emitted script against gnark's E12.Frobenius /
// E12.FrobeniusSquare and assert byte-equality of the 12 Fp slots.
func TestBN254_FrobeniusCoefficients(t *testing.T) {
	p := mustParseBig("21888242871839275222246405745257275088696311157297823662689037894645226208583")
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	// -----------------------------------------------------------------
	// Check 1: γ_{2,3} = p - 1
	// This is the fundamental identity ξ^((p²-1)/2) = -1 in Fp, i.e. p-1.
	// -----------------------------------------------------------------
	if bn254Gamma13Sq[0].Cmp(pMinus1) != 0 {
		t.Errorf("γ_{2,3} c0: want p-1 = %s, got %s", pMinus1, bn254Gamma13Sq[0])
	}
	if bn254Gamma13Sq[1].Sign() != 0 {
		t.Errorf("γ_{2,3} c1: want 0, got %s", bn254Gamma13Sq[1])
	}

	// -----------------------------------------------------------------
	// Check 2: All γ_{2,*} have c1 = 0 (they are Fp elements in Fp2).
	// -----------------------------------------------------------------
	sqCoeffs := [][2]*big.Int{
		bn254Gamma11Sq,
		bn254Gamma12Sq,
		bn254Gamma13Sq,
		bn254Gamma14Sq,
		bn254Gamma15Sq,
	}
	for i, g := range sqCoeffs {
		if g[1].Sign() != 0 {
			t.Errorf("γ_{2,%d} must have c1=0, got %s", i+1, g[1])
		}
	}

	// -----------------------------------------------------------------
	// Check 3: All coefficients (γ_{1,*} and γ_{2,*}) are within [0, p).
	// -----------------------------------------------------------------
	allCoeffs := [][2]*big.Int{
		bn254Gamma11, bn254Gamma12, bn254Gamma13, bn254Gamma14, bn254Gamma15,
		bn254Gamma11Sq, bn254Gamma12Sq, bn254Gamma13Sq, bn254Gamma14Sq, bn254Gamma15Sq,
	}
	names := []string{
		"γ_{1,1}", "γ_{1,2}", "γ_{1,3}", "γ_{1,4}", "γ_{1,5}",
		"γ_{2,1}", "γ_{2,2}", "γ_{2,3}", "γ_{2,4}", "γ_{2,5}",
	}
	for i, g := range allCoeffs {
		if g[0].Sign() < 0 || g[0].Cmp(p) >= 0 {
			t.Errorf("%s c0 out of range [0, p): %s", names[i], g[0])
		}
		if g[1].Sign() < 0 || g[1].Cmp(p) >= 0 {
			t.Errorf("%s c1 out of range [0, p): %s", names[i], g[1])
		}
	}

	// -----------------------------------------------------------------
	// Check 4: Known BN254 identities on γ_{2,*} values.
	//
	// For BN254 with ξ = 9+u, the p²-Frobenius Fp constants satisfy:
	//   γ_{2,1} - γ_{2,2} = 1  (γ_{2,1} is one larger than γ_{2,2})
	//   γ_{2,5} - γ_{2,4} = 1
	// These relationships follow from the BN254 tower construction and
	// match gnark-crypto's MulByNonResidue2PowerK values exactly.
	// -----------------------------------------------------------------
	diff12 := new(big.Int).Sub(bn254Gamma11Sq[0], bn254Gamma12Sq[0])
	if diff12.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("γ_{2,1} - γ_{2,2} = %s, want 1", diff12)
	}

	diff45 := new(big.Int).Sub(bn254Gamma15Sq[0], bn254Gamma14Sq[0])
	if diff45.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("γ_{2,5} - γ_{2,4} = %s, want 1", diff45)
	}

	// -----------------------------------------------------------------
	// Check 5: γ_{1,*} are non-trivial (both components non-zero).
	// A zero coefficient would indicate a copy/paste or init error.
	// -----------------------------------------------------------------
	piP := [][2]*big.Int{
		bn254Gamma11, bn254Gamma12, bn254Gamma13, bn254Gamma14, bn254Gamma15,
	}
	for i, g := range piP {
		if g[0].Sign() == 0 {
			t.Errorf("γ_{1,%d} c0 is zero (likely uninitialised)", i+1)
		}
		if g[1].Sign() == 0 {
			t.Errorf("γ_{1,%d} c1 is zero (likely uninitialised)", i+1)
		}
	}

	// -----------------------------------------------------------------
	// Check 6: γ_{2,*} c0 values are non-zero.
	// -----------------------------------------------------------------
	for i, g := range sqCoeffs {
		if g[0].Sign() == 0 {
			t.Errorf("γ_{2,%d} c0 is zero (likely uninitialised)", i+1)
		}
	}
}
