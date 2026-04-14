// Generates BN254 field arithmetic, G1 curve, and pairing test vectors using
// gnark-crypto as the reference implementation. These vectors validate Rúnar's
// compiled Bitcoin Script BN254 operations.
//
// Output: JSON files in ../../vectors/ for field ops, G1 ops, and pairings.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ---------------------------------------------------------------------------
// JSON types
// ---------------------------------------------------------------------------

type FpVectorFile struct {
	Field   string     `json:"field"`
	Prime   string     `json:"prime"`
	Vectors []FpVector `json:"vectors"`
}

type FpVector struct {
	Op          string  `json:"op"`
	A           string  `json:"a"`
	B           *string `json:"b,omitempty"`
	Expected    string  `json:"expected"`
	Description string  `json:"description"`
}

type G1VectorFile struct {
	Field   string     `json:"field"`
	Curve   string     `json:"curve"`
	Vectors []G1Vector `json:"vectors"`
}

type G1Vector struct {
	Op          string  `json:"op"`
	Ax          string  `json:"ax"`
	Ay          string  `json:"ay"`
	Bx          *string `json:"bx,omitempty"`
	By          *string `json:"by,omitempty"`
	Scalar      *string `json:"scalar,omitempty"`
	ExpectedX   string  `json:"expected_x"`
	ExpectedY   string  `json:"expected_y"`
	Description string  `json:"description"`
}

type PairingVectorFile struct {
	Field   string          `json:"field"`
	Vectors []PairingVector `json:"vectors"`
}

type PairingVector struct {
	Op          string   `json:"op"`
	G1Points    []string `json:"g1_points"`
	G2Points    []string `json:"g2_points"`
	ExpectedGT  []string `json:"expected_gt"`
	IsOne       bool     `json:"is_one"`
	Description string   `json:"description"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fpToHex returns a 64-char zero-padded hex string (32 bytes big-endian).
func fpToHex(f *fp.Element) string {
	b := f.Bytes()
	return fmt.Sprintf("%064x", new(big.Int).SetBytes(b[:]))
}

// fpFromU64 creates an fp.Element from a uint64.
func fpFromU64(v uint64) fp.Element {
	var f fp.Element
	f.SetUint64(v)
	return f
}

// fpFromBig creates an fp.Element from a *big.Int.
func fpFromBig(v *big.Int) fp.Element {
	var f fp.Element
	f.SetBigInt(v)
	return f
}

// g1ToHex returns (x_hex, y_hex) for an affine G1 point.
func g1ToHex(p *bn254.G1Affine) (string, string) {
	xb := p.X.Bytes()
	yb := p.Y.Bytes()
	return fmt.Sprintf("%064x", new(big.Int).SetBytes(xb[:])),
		fmt.Sprintf("%064x", new(big.Int).SetBytes(yb[:]))
}

// strPtr returns a pointer to a string (for optional JSON fields).
func strPtr(s string) *string { return &s }

var fpP *big.Int

func init() {
	fpP, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
}

// ---------------------------------------------------------------------------
// Field arithmetic vector generators
// ---------------------------------------------------------------------------

func generateFpAddVectors() []FpVector {
	var vecs []FpVector
	rng := rand.New(rand.NewSource(42))

	add := func(a, b fp.Element, desc string) {
		var r fp.Element
		r.Add(&a, &b)
		bh := fpToHex(&b)
		vecs = append(vecs, FpVector{Op: "add", A: fpToHex(&a), B: &bh, Expected: fpToHex(&r), Description: desc})
	}

	// Edge cases
	add(fpFromU64(0), fpFromU64(0), "0 + 0 = 0")
	add(fpFromU64(1), fpFromU64(0), "1 + 0 = 1")
	add(fpFromU64(0), fpFromU64(1), "0 + 1 = 1")
	pMinus1 := fpFromBig(new(big.Int).Sub(fpP, big.NewInt(1)))
	add(pMinus1, fpFromU64(1), "(p-1) + 1 = 0")
	add(pMinus1, pMinus1, "(p-1) + (p-1) = p-2")

	// Small values
	for i := uint64(1); i <= 10; i++ {
		for j := uint64(1); j <= 10; j++ {
			add(fpFromU64(i), fpFromU64(j), fmt.Sprintf("%d + %d", i, j))
		}
	}

	// Random values
	for i := 0; i < 50; i++ {
		var a, b fp.Element
		a.SetUint64(rng.Uint64())
		b.SetUint64(rng.Uint64())
		add(a, b, fmt.Sprintf("random #%d", i))
	}

	return vecs
}

func generateFpSubVectors() []FpVector {
	var vecs []FpVector
	rng := rand.New(rand.NewSource(43))

	sub := func(a, b fp.Element, desc string) {
		var r fp.Element
		r.Sub(&a, &b)
		bh := fpToHex(&b)
		vecs = append(vecs, FpVector{Op: "sub", A: fpToHex(&a), B: &bh, Expected: fpToHex(&r), Description: desc})
	}

	sub(fpFromU64(0), fpFromU64(0), "0 - 0 = 0")
	sub(fpFromU64(1), fpFromU64(0), "1 - 0 = 1")
	sub(fpFromU64(0), fpFromU64(1), "0 - 1 = p-1")
	pMinus1 := fpFromBig(new(big.Int).Sub(fpP, big.NewInt(1)))
	sub(fpFromU64(1), pMinus1, "1 - (p-1) = 2")
	sub(pMinus1, pMinus1, "(p-1) - (p-1) = 0")

	for i := uint64(0); i <= 10; i++ {
		for j := uint64(0); j <= 10; j++ {
			sub(fpFromU64(i), fpFromU64(j), fmt.Sprintf("%d - %d", i, j))
		}
	}

	for i := 0; i < 50; i++ {
		var a, b fp.Element
		a.SetUint64(rng.Uint64())
		b.SetUint64(rng.Uint64())
		sub(a, b, fmt.Sprintf("random #%d", i))
	}

	return vecs
}

func generateFpMulVectors() []FpVector {
	var vecs []FpVector
	rng := rand.New(rand.NewSource(44))

	mul := func(a, b fp.Element, desc string) {
		var r fp.Element
		r.Mul(&a, &b)
		bh := fpToHex(&b)
		vecs = append(vecs, FpVector{Op: "mul", A: fpToHex(&a), B: &bh, Expected: fpToHex(&r), Description: desc})
	}

	mul(fpFromU64(0), fpFromU64(0), "0 * 0 = 0")
	mul(fpFromU64(1), fpFromU64(0), "1 * 0 = 0")
	mul(fpFromU64(1), fpFromU64(1), "1 * 1 = 1")
	pMinus1 := fpFromBig(new(big.Int).Sub(fpP, big.NewInt(1)))
	mul(pMinus1, pMinus1, "(-1) * (-1) = 1")
	mul(pMinus1, fpFromU64(2), "(-1) * 2 = p-2")

	for i := uint64(1); i <= 12; i++ {
		for j := uint64(1); j <= 12; j++ {
			mul(fpFromU64(i), fpFromU64(j), fmt.Sprintf("%d * %d", i, j))
		}
	}

	for i := 0; i < 50; i++ {
		var a, b fp.Element
		a.SetUint64(rng.Uint64())
		b.SetUint64(rng.Uint64())
		mul(a, b, fmt.Sprintf("random #%d", i))
	}

	return vecs
}

func generateFpInvVectors() []FpVector {
	var vecs []FpVector
	rng := rand.New(rand.NewSource(45))

	inv := func(a fp.Element, desc string) {
		var r fp.Element
		r.Inverse(&a)
		vecs = append(vecs, FpVector{Op: "inv", A: fpToHex(&a), Expected: fpToHex(&r), Description: desc})
	}

	inv(fpFromU64(1), "inv(1) = 1")
	inv(fpFromU64(2), "inv(2)")
	pMinus1 := fpFromBig(new(big.Int).Sub(fpP, big.NewInt(1)))
	inv(pMinus1, "inv(p-1) = p-1")

	for i := uint64(1); i <= 50; i++ {
		inv(fpFromU64(i), fmt.Sprintf("inv(%d)", i))
	}

	for i := 0; i < 30; i++ {
		var a fp.Element
		a.SetUint64(rng.Uint64() | 1) // ensure non-zero
		inv(a, fmt.Sprintf("random inv #%d", i))
	}

	return vecs
}

// ---------------------------------------------------------------------------
// G1 curve operation vector generators
// ---------------------------------------------------------------------------

func generateG1AddVectors() []G1Vector {
	var vecs []G1Vector

	// Generator
	_, _, g1Gen, _ := bn254.Generators()

	// Compute small multiples: 1G, 2G, ..., 10G
	points := make([]bn254.G1Affine, 11)
	// points[0] is zero-value (point at infinity)
	points[1].Set(&g1Gen)
	for i := 2; i <= 10; i++ {
		points[i].Add(&points[i-1], &g1Gen)
	}

	// Addition tests: iG + jG = (i+j)G
	for i := 1; i <= 5; i++ {
		for j := 1; j <= 5; j++ {
			var sum bn254.G1Affine
			sum.Add(&points[i], &points[j])
			ax, ay := g1ToHex(&points[i])
			bx, by := g1ToHex(&points[j])
			ex, ey := g1ToHex(&sum)
			vecs = append(vecs, G1Vector{
				Op: "add", Ax: ax, Ay: ay, Bx: strPtr(bx), By: strPtr(by),
				ExpectedX: ex, ExpectedY: ey,
				Description: fmt.Sprintf("%dG + %dG = %dG", i, j, i+j),
			})
		}
	}

	// P + (-P) = infinity — skip since infinity isn't a normal affine point

	return vecs
}

func generateG1ScalarMulVectors() []G1Vector {
	var vecs []G1Vector

	_, _, g1Gen, _ := bn254.Generators()

	// Small scalars
	for i := int64(1); i <= 10; i++ {
		var result bn254.G1Affine
		var s big.Int
		s.SetInt64(i)
		result.ScalarMultiplication(&g1Gen, &s)
		ex, ey := g1ToHex(&result)
		gx, gy := g1ToHex(&g1Gen)
		sc := fmt.Sprintf("%064x", &s)
		vecs = append(vecs, G1Vector{
			Op: "scalar_mul", Ax: gx, Ay: gy, Scalar: strPtr(sc),
			ExpectedX: ex, ExpectedY: ey,
			Description: fmt.Sprintf("%d * G", i),
		})
	}

	// Powers of 2
	for k := uint(1); k <= 10; k++ {
		var result bn254.G1Affine
		s := new(big.Int).Lsh(big.NewInt(1), k)
		result.ScalarMultiplication(&g1Gen, s)
		ex, ey := g1ToHex(&result)
		gx, gy := g1ToHex(&g1Gen)
		sc := fmt.Sprintf("%064x", s)
		vecs = append(vecs, G1Vector{
			Op: "scalar_mul", Ax: gx, Ay: gy, Scalar: strPtr(sc),
			ExpectedX: ex, ExpectedY: ey,
			Description: fmt.Sprintf("2^%d * G", k),
		})
	}

	// Random scalars
	rng := rand.New(rand.NewSource(46))
	for i := 0; i < 5; i++ {
		var result bn254.G1Affine
		var s fr.Element
		s.SetUint64(rng.Uint64())
		var sBig big.Int
		s.BigInt(&sBig)
		result.ScalarMultiplication(&g1Gen, &sBig)
		ex, ey := g1ToHex(&result)
		gx, gy := g1ToHex(&g1Gen)
		sc := fmt.Sprintf("%064x", &sBig)
		vecs = append(vecs, G1Vector{
			Op: "scalar_mul", Ax: gx, Ay: gy, Scalar: strPtr(sc),
			ExpectedX: ex, ExpectedY: ey,
			Description: fmt.Sprintf("random scalar #%d * G", i),
		})
	}

	return vecs
}

// ---------------------------------------------------------------------------
// Pairing vector generators
// ---------------------------------------------------------------------------

func generatePairingVectors() []PairingVector {
	var vecs []PairingVector

	_, _, g1Gen, g2Gen := bn254.Generators()

	// e(G1, G2)
	gt, err := bn254.Pair([]bn254.G1Affine{g1Gen}, []bn254.G2Affine{g2Gen})
	if err != nil {
		panic(fmt.Sprintf("pairing failed: %v", err))
	}
	vecs = append(vecs, PairingVector{
		Op:          "single_pairing",
		G1Points:    g1AffineToHexSlice(g1Gen),
		G2Points:    g2AffineToHexSlice(g2Gen),
		ExpectedGT:  gtToHexSlice(&gt),
		IsOne:       false,
		Description: "e(G1, G2) — generator pairing",
	})

	// Bilinearity: e(2G1, G2) == e(G1, 2G2)
	var g1x2 bn254.G1Affine
	g1x2.Add(&g1Gen, &g1Gen)
	gt2a, _ := bn254.Pair([]bn254.G1Affine{g1x2}, []bn254.G2Affine{g2Gen})

	var g2x2 bn254.G2Affine
	g2x2.Add(&g2Gen, &g2Gen)
	gt2b, _ := bn254.Pair([]bn254.G1Affine{g1Gen}, []bn254.G2Affine{g2x2})

	vecs = append(vecs, PairingVector{
		Op:          "single_pairing",
		G1Points:    g1AffineToHexSlice(g1x2),
		G2Points:    g2AffineToHexSlice(g2Gen),
		ExpectedGT:  gtToHexSlice(&gt2a),
		IsOne:       false,
		Description: "e(2*G1, G2) — bilinearity check LHS",
	})

	vecs = append(vecs, PairingVector{
		Op:          "single_pairing",
		G1Points:    g1AffineToHexSlice(g1Gen),
		G2Points:    g2AffineToHexSlice(g2x2),
		ExpectedGT:  gtToHexSlice(&gt2b),
		IsOne:       false,
		Description: "e(G1, 2*G2) — bilinearity check RHS (should equal LHS)",
	})

	// Product pairing: e(aG1, G2) * e(-G1, aG2) == 1
	// This is the Groth16-style check pattern
	a := big.NewInt(42)
	var aG1 bn254.G1Affine
	aG1.ScalarMultiplication(&g1Gen, a)
	var negG1 bn254.G1Affine
	negG1.Neg(&g1Gen)
	var aG2 bn254.G2Affine
	aG2.ScalarMultiplication(&g2Gen, a)

	prodCheck, _ := bn254.Pair(
		[]bn254.G1Affine{aG1, negG1},
		[]bn254.G2Affine{g2Gen, aG2},
	)

	vecs = append(vecs, PairingVector{
		Op:          "product_pairing",
		G1Points:    append(g1AffineToHexSlice(aG1), g1AffineToHexSlice(negG1)...),
		G2Points:    append(g2AffineToHexSlice(g2Gen), g2AffineToHexSlice(aG2)...),
		ExpectedGT:  gtToHexSlice(&prodCheck),
		IsOne:       true,
		Description: "e(42*G1, G2) * e(-G1, 42*G2) = 1 (Groth16-style product)",
	})

	return vecs
}

func g1AffineToHexSlice(p bn254.G1Affine) []string {
	x, y := g1ToHex(&p)
	return []string{x, y}
}

func g2AffineToHexSlice(p bn254.G2Affine) []string {
	// G2 point has Fp2 coordinates: X = (X.A0, X.A1), Y = (Y.A0, Y.A1)
	xa0 := p.X.A0.Bytes()
	xa1 := p.X.A1.Bytes()
	ya0 := p.Y.A0.Bytes()
	ya1 := p.Y.A1.Bytes()
	return []string{
		fmt.Sprintf("%064x", new(big.Int).SetBytes(xa0[:])),
		fmt.Sprintf("%064x", new(big.Int).SetBytes(xa1[:])),
		fmt.Sprintf("%064x", new(big.Int).SetBytes(ya0[:])),
		fmt.Sprintf("%064x", new(big.Int).SetBytes(ya1[:])),
	}
}

func gtToHexSlice(gt *bn254.GT) []string {
	// GT is Fp12 = Fp6[w]/(w^2 - v), Fp6 = Fp2[v]/(v^3 - xi)
	// Marshal as 12 Fp elements in gnark-crypto's canonical order
	b := gt.Marshal()
	result := make([]string, 12)
	for i := 0; i < 12; i++ {
		elem := new(big.Int).SetBytes(b[i*32 : (i+1)*32])
		result[i] = fmt.Sprintf("%064x", elem)
	}
	return result
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	vectorsDir := filepath.Join("..", "..", "vectors")
	if err := os.MkdirAll(vectorsDir, 0o755); err != nil {
		log.Fatalf("create vectors dir: %v", err)
	}

	// Field arithmetic vectors
	for _, tc := range []struct {
		name string
		gen  func() []FpVector
	}{
		{"bn254_fp_add", generateFpAddVectors},
		{"bn254_fp_sub", generateFpSubVectors},
		{"bn254_fp_mul", generateFpMulVectors},
		{"bn254_fp_inv", generateFpInvVectors},
	} {
		vecs := tc.gen()
		file := FpVectorFile{
			Field:   "bn254_fp",
			Prime:   fpP.String(),
			Vectors: vecs,
		}
		data, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			log.Fatalf("json marshal %s: %v", tc.name, err)
		}
		path := filepath.Join(vectorsDir, tc.name+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatalf("write %s: %v", path, err)
		}
		fmt.Printf("Generated %d vectors in %s\n", len(vecs), tc.name)
	}

	// G1 vectors
	addVecs := generateG1AddVectors()
	smVecs := generateG1ScalarMulVectors()
	allG1 := append(addVecs, smVecs...)
	g1File := G1VectorFile{
		Field:   "bn254",
		Curve:   "y^2 = x^3 + 3",
		Vectors: allG1,
	}
	g1Data, err := json.MarshalIndent(g1File, "", "  ")
	if err != nil {
		log.Fatalf("json marshal g1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vectorsDir, "bn254_g1.json"), g1Data, 0o644); err != nil {
		log.Fatalf("write g1: %v", err)
	}
	fmt.Printf("Generated %d G1 vectors\n", len(allG1))

	// Pairing vectors
	pairingVecs := generatePairingVectors()
	pFile := PairingVectorFile{
		Field:   "bn254",
		Vectors: pairingVecs,
	}
	pData, err := json.MarshalIndent(pFile, "", "  ")
	if err != nil {
		log.Fatalf("json marshal pairing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vectorsDir, "bn254_pairing.json"), pData, 0o644); err != nil {
		log.Fatalf("write pairing: %v", err)
	}
	fmt.Printf("Generated %d pairing vectors\n", len(pairingVecs))

	fmt.Println("\nAll BN254 test vectors written.")
}
