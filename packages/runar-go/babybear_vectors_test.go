package runar

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// BabyBear base-field KAT tests
//
// Vectors sourced from Plonky3 baby-bear (same JSON format as KoalaBear).
// Mirrors coverage of koalabear_vectors_test.go for parity.
// ---------------------------------------------------------------------------

type bbVectorFile struct {
	Field   string     `json:"field"`
	Prime   int64      `json:"prime"`
	Vectors []bbVector `json:"vectors"`
}

type bbVector struct {
	Op       string `json:"op"`
	A        int64  `json:"a"`
	B        int64  `json:"b,omitempty"`
	Expected int64  `json:"expected"`
	Desc     string `json:"description"`
}

func loadBBVectors(t *testing.T, filename string) bbVectorFile {
	t.Helper()
	data, err := os.ReadFile("../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf bbVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

func TestBBField_Add_Plonky3Vectors(t *testing.T) {
	vf := loadBBVectors(t, "babybear_add.json")
	t.Logf("loaded %d addition vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := BbFieldAdd(v.A, v.B)
			if got != v.Expected {
				t.Errorf("BbFieldAdd(%d, %d) = %d, want %d", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestBBField_Sub_Plonky3Vectors(t *testing.T) {
	vf := loadBBVectors(t, "babybear_sub.json")
	t.Logf("loaded %d subtraction vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := BbFieldSub(v.A, v.B)
			if got != v.Expected {
				t.Errorf("BbFieldSub(%d, %d) = %d, want %d", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestBBField_Mul_Plonky3Vectors(t *testing.T) {
	vf := loadBBVectors(t, "babybear_mul.json")
	t.Logf("loaded %d multiplication vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := BbFieldMul(v.A, v.B)
			if got != v.Expected {
				t.Errorf("BbFieldMul(%d, %d) = %d, want %d", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestBBField_Inv_Plonky3Vectors(t *testing.T) {
	vf := loadBBVectors(t, "babybear_inv.json")
	t.Logf("loaded %d inverse vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := BbFieldInv(v.A)
			if got != v.Expected {
				t.Errorf("BbFieldInv(%d) = %d, want %d", v.A, got, v.Expected)
			}
		})
	}
}
