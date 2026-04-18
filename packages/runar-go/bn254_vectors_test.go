package runar

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

type bn254FpVectorFile struct {
	Field   string         `json:"field"`
	Prime   string         `json:"prime"`
	Vectors []bn254FpVec   `json:"vectors"`
}

type bn254FpVec struct {
	Op       string  `json:"op"`
	A        string  `json:"a"`
	B        *string `json:"b,omitempty"`
	Expected string  `json:"expected"`
	Desc     string  `json:"description"`
}

func hexToBigInt(h string) *big.Int {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("hexToBigInt: invalid hex: " + h)
	}
	return new(big.Int).SetBytes(b)
}

func loadBN254FpVectors(t *testing.T, filename string) []bn254FpVec {
	t.Helper()
	data, err := os.ReadFile("../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var f bn254FpVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("no vectors loaded from %s", filename)
	}
	return f.Vectors
}

func TestBN254Field_Add_GnarkVectors(t *testing.T) {
	vecs := loadBN254FpVectors(t, "bn254_fp_add.json")
	for _, v := range vecs {
		t.Run(v.Desc, func(t *testing.T) {
			a := hexToBigInt(v.A)
			b := hexToBigInt(*v.B)
			expected := hexToBigInt(v.Expected)
			got := Bn254FieldAdd(a, b)
			if got.Cmp(expected) != 0 {
				t.Errorf("got %s, want %s", got.Text(16), expected.Text(16))
			}
		})
	}
}

func TestBN254Field_Sub_GnarkVectors(t *testing.T) {
	vecs := loadBN254FpVectors(t, "bn254_fp_sub.json")
	for _, v := range vecs {
		t.Run(v.Desc, func(t *testing.T) {
			a := hexToBigInt(v.A)
			b := hexToBigInt(*v.B)
			expected := hexToBigInt(v.Expected)
			got := Bn254FieldSub(a, b)
			if got.Cmp(expected) != 0 {
				t.Errorf("got %s, want %s", got.Text(16), expected.Text(16))
			}
		})
	}
}

func TestBN254Field_Mul_GnarkVectors(t *testing.T) {
	vecs := loadBN254FpVectors(t, "bn254_fp_mul.json")
	for _, v := range vecs {
		t.Run(v.Desc, func(t *testing.T) {
			a := hexToBigInt(v.A)
			b := hexToBigInt(*v.B)
			expected := hexToBigInt(v.Expected)
			got := Bn254FieldMul(a, b)
			if got.Cmp(expected) != 0 {
				t.Errorf("got %s, want %s", got.Text(16), expected.Text(16))
			}
		})
	}
}

func TestBN254Field_Inv_GnarkVectors(t *testing.T) {
	vecs := loadBN254FpVectors(t, "bn254_fp_inv.json")
	for _, v := range vecs {
		t.Run(v.Desc, func(t *testing.T) {
			a := hexToBigInt(v.A)
			expected := hexToBigInt(v.Expected)
			got := Bn254FieldInv(a)
			if got.Cmp(expected) != 0 {
				t.Errorf("got %s, want %s", got.Text(16), expected.Text(16))
			}
		})
	}
}

// --- G1 curve operation tests ---

type bn254G1VectorFile struct {
	Field   string       `json:"field"`
	Curve   string       `json:"curve"`
	Vectors []bn254G1Vec `json:"vectors"`
}

type bn254G1Vec struct {
	Op        string  `json:"op"`
	Ax        string  `json:"ax"`
	Ay        string  `json:"ay"`
	Bx        *string `json:"bx,omitempty"`
	By        *string `json:"by,omitempty"`
	Scalar    *string `json:"scalar,omitempty"`
	ExpectedX string  `json:"expected_x"`
	ExpectedY string  `json:"expected_y"`
	Desc      string  `json:"description"`
}

func loadBN254G1Vectors(t *testing.T) []bn254G1Vec {
	t.Helper()
	data, err := os.ReadFile("../../tests/vectors/bn254_g1.json")
	if err != nil {
		t.Fatalf("load G1 vectors: %v", err)
	}
	var f bn254G1VectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse G1 vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no G1 vectors loaded")
	}
	return f.Vectors
}

func hexToPoint(xHex, yHex string) []byte {
	x := hexToBigInt(xHex)
	y := hexToBigInt(yHex)
	buf := make([]byte, 64)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(buf[32-len(xBytes):32], xBytes)
	copy(buf[64-len(yBytes):64], yBytes)
	return buf
}

func TestBN254G1_Add_GnarkVectors(t *testing.T) {
	vecs := loadBN254G1Vectors(t)
	for _, v := range vecs {
		if v.Op != "add" {
			continue
		}
		t.Run(v.Desc, func(t *testing.T) {
			p1 := hexToPoint(v.Ax, v.Ay)
			p2 := hexToPoint(*v.Bx, *v.By)
			expected := hexToPoint(v.ExpectedX, v.ExpectedY)
			got := Bn254G1Add(p1, p2)
			if !bytesEqual(got, expected) {
				t.Errorf("got %x, want %x", got, expected)
			}
		})
	}
}

func TestBN254G1_ScalarMul_GnarkVectors(t *testing.T) {
	vecs := loadBN254G1Vectors(t)
	for _, v := range vecs {
		if v.Op != "scalar_mul" {
			continue
		}
		t.Run(v.Desc, func(t *testing.T) {
			p := hexToPoint(v.Ax, v.Ay)
			s := hexToBigInt(*v.Scalar)
			expected := hexToPoint(v.ExpectedX, v.ExpectedY)
			got := Bn254G1ScalarMul(p, s)
			if !bytesEqual(got, expected) {
				t.Errorf("got %x, want %x", got, expected)
			}
		})
	}
}

func TestBN254G1_Negate(t *testing.T) {
	// Negating the generator and adding it back should give the identity point
	gen := hexToPoint(
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)
	neg := Bn254G1Negate(gen)
	sum := Bn254G1Add(gen, neg)
	identity := make([]byte, 64)
	if !bytesEqual(sum, identity) {
		t.Errorf("G + (-G) should be identity, got %x", sum)
	}

	// Negating the identity should return identity
	negIdentity := Bn254G1Negate(identity)
	if !bytesEqual(negIdentity, identity) {
		t.Errorf("negating identity should return identity, got %x", negIdentity)
	}

	// Double-negation should return the original point
	doubleNeg := Bn254G1Negate(neg)
	if !bytesEqual(doubleNeg, gen) {
		t.Errorf("double negation should return original, got %x, want %x", doubleNeg, gen)
	}
}

func TestBN254G1_OnCurve(t *testing.T) {
	vecs := loadBN254G1Vectors(t)

	// All input points from vectors should be on the curve
	for _, v := range vecs {
		p := hexToPoint(v.Ax, v.Ay)
		if !Bn254G1OnCurve(p) {
			t.Errorf("point (%s, %s) from vector %q should be on curve", v.Ax, v.Ay, v.Desc)
		}
		ep := hexToPoint(v.ExpectedX, v.ExpectedY)
		if !Bn254G1OnCurve(ep) {
			t.Errorf("expected point (%s, %s) from vector %q should be on curve", v.ExpectedX, v.ExpectedY, v.Desc)
		}
	}

	// Identity point (0, 0) is rejected to match compiled Script codegen
	// (EmitBN254G1OnCurve evaluates y² == x³ + 3 directly; 0 ≠ 3).
	identity := make([]byte, 64)
	if Bn254G1OnCurve(identity) {
		t.Error("identity point (0,0) should be rejected: Script codegen rejects it")
	}

	// A random off-curve point should NOT be on the curve
	offCurve := hexToPoint(
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000003",
	)
	if Bn254G1OnCurve(offCurve) {
		t.Error("point (1, 3) should NOT be on the BN254 curve")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
