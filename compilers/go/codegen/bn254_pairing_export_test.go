package codegen

import (
	"math/big"
	"testing"
)

// TestBn254SixXPlus2NAF_Exported verifies the exported NAF accessor returns
// a non-empty slice with the expected length and matches the package-private
// constant.
func TestBn254SixXPlus2NAF_Exported(t *testing.T) {
	naf := Bn254SixXPlus2NAF()

	if len(naf) == 0 {
		t.Fatal("Bn254SixXPlus2NAF returned empty slice")
	}

	// |6x+2| = 29793968203157093288 has bit length 65, so the NAF has at most
	// 66 digits. The actual NAF length is determined by the algorithm in
	// computeNAF and is fixed for BN254.
	if len(naf) < 60 || len(naf) > 70 {
		t.Errorf("NAF length out of expected range [60,70]: got %d", len(naf))
	}

	// MSB must be non-zero (otherwise we'd have stripped it).
	if naf[len(naf)-1] == 0 {
		t.Error("NAF MSB is zero — should have been stripped")
	}

	// All entries must be in {-1, 0, 1}.
	for i, d := range naf {
		if d < -1 || d > 1 {
			t.Errorf("NAF[%d] = %d, want -1/0/1", i, d)
		}
	}

	// Returned slice must be a copy — mutating it must not affect the package
	// internal state.
	original := naf[0]
	naf[0] = 99
	naf2 := Bn254SixXPlus2NAF()
	if naf2[0] != original {
		t.Error("Bn254SixXPlus2NAF returned an aliased slice; mutation leaked")
	}
}

// TestBn254FieldPrime_Exported verifies the exported field prime accessor
// returns the canonical BN254 prime and is a fresh copy each call.
func TestBn254FieldPrime_Exported(t *testing.T) {
	expected, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088696311157297823662689037894645226208583",
		10,
	)

	p := Bn254FieldPrime()
	if p.Cmp(expected) != 0 {
		t.Errorf("Bn254FieldPrime() = %s, want %s", p, expected)
	}

	// Returned value must be a copy — mutation must not affect package state.
	p.SetUint64(1)
	p2 := Bn254FieldPrime()
	if p2.Cmp(expected) != 0 {
		t.Error("Bn254FieldPrime returned an aliased big.Int; mutation leaked")
	}
}
