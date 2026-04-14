package runar

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// JSON vector types
// ---------------------------------------------------------------------------

type kbVectorFile struct {
	Field   string     `json:"field"`
	Prime   int64      `json:"prime"`
	Vectors []kbVector `json:"vectors"`
}

type kbVector struct {
	Op       string `json:"op"`
	A        int64  `json:"a"`
	B        int64  `json:"b,omitempty"`
	Expected int64  `json:"expected"`
	Desc     string `json:"description"`
}

func loadKBVectors(t *testing.T, filename string) kbVectorFile {
	t.Helper()
	data, err := os.ReadFile("../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf kbVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

// ---------------------------------------------------------------------------
// Base field tests
// ---------------------------------------------------------------------------

func TestKBField_Add_Plonky3Vectors(t *testing.T) {
	vf := loadKBVectors(t, "koalabear_add.json")
	t.Logf("loaded %d addition vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := KbFieldAdd(v.A, v.B)
			if got != v.Expected {
				t.Errorf("KbFieldAdd(%d, %d) = %d, want %d", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestKBField_Sub_Plonky3Vectors(t *testing.T) {
	vf := loadKBVectors(t, "koalabear_sub.json")
	t.Logf("loaded %d subtraction vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := KbFieldSub(v.A, v.B)
			if got != v.Expected {
				t.Errorf("KbFieldSub(%d, %d) = %d, want %d", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestKBField_Mul_Plonky3Vectors(t *testing.T) {
	vf := loadKBVectors(t, "koalabear_mul.json")
	t.Logf("loaded %d multiplication vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := KbFieldMul(v.A, v.B)
			if got != v.Expected {
				t.Errorf("KbFieldMul(%d, %d) = %d, want %d", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestKBField_Inv_Plonky3Vectors(t *testing.T) {
	vf := loadKBVectors(t, "koalabear_inv.json")
	t.Logf("loaded %d inverse vectors", len(vf.Vectors))

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			got := KbFieldInv(v.A)
			if got != v.Expected {
				t.Errorf("KbFieldInv(%d) = %d, want %d", v.A, got, v.Expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Ext4 field tests
// ---------------------------------------------------------------------------

type kbExt4VectorFile struct {
	Field   string         `json:"field"`
	W       int64          `json:"W"`
	Vectors []kbExt4Vector `json:"vectors"`
}

type kbExt4Vector struct {
	Op       string  `json:"op"`
	A        [4]int64 `json:"a"`
	B        [4]int64 `json:"b,omitempty"`
	Expected [4]int64 `json:"expected"`
	Desc     string   `json:"description"`
}

func loadKBExt4Vectors(t *testing.T, filename string) kbExt4VectorFile {
	t.Helper()
	data, err := os.ReadFile("../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf kbExt4VectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

func TestKBExt4_Mul_Plonky3Vectors(t *testing.T) {
	vf := loadKBExt4Vectors(t, "koalabear_ext4_mul.json")
	t.Logf("loaded %d ext4 mul vectors (W=%d)", len(vf.Vectors), vf.W)

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			r0 := KbExt4Mul0(v.A[0], v.A[1], v.A[2], v.A[3], v.B[0], v.B[1], v.B[2], v.B[3])
			r1 := KbExt4Mul1(v.A[0], v.A[1], v.A[2], v.A[3], v.B[0], v.B[1], v.B[2], v.B[3])
			r2 := KbExt4Mul2(v.A[0], v.A[1], v.A[2], v.A[3], v.B[0], v.B[1], v.B[2], v.B[3])
			r3 := KbExt4Mul3(v.A[0], v.A[1], v.A[2], v.A[3], v.B[0], v.B[1], v.B[2], v.B[3])
			got := [4]int64{r0, r1, r2, r3}
			if got != v.Expected {
				t.Errorf("KbExt4Mul(%v, %v) = %v, want %v", v.A, v.B, got, v.Expected)
			}
		})
	}
}

func TestKBExt4_Inv_Plonky3Vectors(t *testing.T) {
	vf := loadKBExt4Vectors(t, "koalabear_ext4_inv.json")
	t.Logf("loaded %d ext4 inv vectors (W=%d)", len(vf.Vectors), vf.W)

	for i, v := range vf.Vectors {
		v := v
		t.Run(fmt.Sprintf("%d_%s", i, v.Desc), func(t *testing.T) {
			r0 := KbExt4Inv0(v.A[0], v.A[1], v.A[2], v.A[3])
			r1 := KbExt4Inv1(v.A[0], v.A[1], v.A[2], v.A[3])
			r2 := KbExt4Inv2(v.A[0], v.A[1], v.A[2], v.A[3])
			r3 := KbExt4Inv3(v.A[0], v.A[1], v.A[2], v.A[3])
			got := [4]int64{r0, r1, r2, r3}
			if got != v.Expected {
				t.Errorf("KbExt4Inv(%v) = %v, want %v", v.A, got, v.Expected)
			}
		})
	}
}

// TestKBExt4_MulInv_Identity verifies a * inv(a) == 1 for the quartic extension.
func TestKBExt4_MulInv_Identity(t *testing.T) {
	testCases := [][4]int64{
		{1, 0, 0, 0},        // identity
		{42, 7, 13, 99},     // arbitrary
		{1000000, 500000, 250000, 125000},
		{2130706432, 1, 2130706432, 1}, // p-1 values
	}

	for _, a := range testCases {
		inv0 := KbExt4Inv0(a[0], a[1], a[2], a[3])
		inv1 := KbExt4Inv1(a[0], a[1], a[2], a[3])
		inv2 := KbExt4Inv2(a[0], a[1], a[2], a[3])
		inv3 := KbExt4Inv3(a[0], a[1], a[2], a[3])

		// a * inv(a) should equal (1, 0, 0, 0)
		r0 := KbExt4Mul0(a[0], a[1], a[2], a[3], inv0, inv1, inv2, inv3)
		r1 := KbExt4Mul1(a[0], a[1], a[2], a[3], inv0, inv1, inv2, inv3)
		r2 := KbExt4Mul2(a[0], a[1], a[2], a[3], inv0, inv1, inv2, inv3)
		r3 := KbExt4Mul3(a[0], a[1], a[2], a[3], inv0, inv1, inv2, inv3)

		// Normalize to [0, p)
		r0 = ((r0 % kbP) + kbP) % kbP
		r1 = ((r1 % kbP) + kbP) % kbP
		r2 = ((r2 % kbP) + kbP) % kbP
		r3 = ((r3 % kbP) + kbP) % kbP

		if r0 != 1 || r1 != 0 || r2 != 0 || r3 != 0 {
			t.Errorf("a=%v: a*inv(a) = (%d, %d, %d, %d), want (1, 0, 0, 0)", a, r0, r1, r2, r3)
		}
	}
}
