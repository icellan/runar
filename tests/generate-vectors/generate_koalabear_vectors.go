// generate_koalabear_vectors.go
//
// CANONICAL vector generator for KoalaBear field arithmetic test vectors.
// The Rust generator (src/generate_koalabear_vectors.rs) serves as a
// cross-validation reference but uses a different PRNG (ChaCha vs Go's
// Lagged Fibonacci), so random vectors differ. Regenerate vectors with
// this Go program — the Rust generator is for independent verification only.
//
// Generates base field + ext4 vectors and writes JSON to ../vectors/.
//
// KoalaBear prime: p = 2130706433 (0x7f000001)
// Extension field: degree 4, irreducible x^4 - 3, so W = 3
//
// Usage: go run generate_koalabear_vectors.go

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
)

// KoalaBear prime p = 2130706433 = 0x7f000001
var P = big.NewInt(2130706433)

// Extension field parameter W = 3
var W = big.NewInt(3)

// ─── Base field arithmetic (mod p) ──────────────────────────────────

func modP(x *big.Int) uint64 {
	r := new(big.Int).Mod(x, P)
	if r.Sign() < 0 {
		r.Add(r, P)
	}
	return r.Uint64()
}

func fieldAdd(a, b uint64) uint64 {
	return modP(new(big.Int).Add(big.NewInt(int64(a)), big.NewInt(int64(b))))
}

func fieldSub(a, b uint64) uint64 {
	return modP(new(big.Int).Sub(big.NewInt(int64(a)), big.NewInt(int64(b))))
}

func fieldMul(a, b uint64) uint64 {
	return modP(new(big.Int).Mul(big.NewInt(int64(a)), big.NewInt(int64(b))))
}

func fieldInv(a uint64) uint64 {
	// a^(p-2) mod p via Fermat's little theorem
	return modP(new(big.Int).Exp(big.NewInt(int64(a)), new(big.Int).Sub(P, big.NewInt(2)), P))
}

// ─── Extension field (degree 4, W=3) ───────────────────────────────
// Elements are [a0, a1, a2, a3] representing a0 + a1*x + a2*x^2 + a3*x^3
// where x^4 = W = 3.

type Ext4 [4]uint64

func ext4Mul(a, b Ext4) Ext4 {
	// Use big.Int for all intermediate products to avoid overflow.
	ba := [4]*big.Int{big.NewInt(int64(a[0])), big.NewInt(int64(a[1])), big.NewInt(int64(a[2])), big.NewInt(int64(a[3]))}
	bb := [4]*big.Int{big.NewInt(int64(b[0])), big.NewInt(int64(b[1])), big.NewInt(int64(b[2])), big.NewInt(int64(b[3]))}

	// r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
	r0 := new(big.Int)
	r0.Mul(ba[0], bb[0])
	t := new(big.Int).Mul(ba[1], bb[3])
	t.Add(t, new(big.Int).Mul(ba[2], bb[2]))
	t.Add(t, new(big.Int).Mul(ba[3], bb[1]))
	t.Mul(t, W)
	r0.Add(r0, t)

	// r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
	r1 := new(big.Int).Mul(ba[0], bb[1])
	r1.Add(r1, new(big.Int).Mul(ba[1], bb[0]))
	t = new(big.Int).Mul(ba[2], bb[3])
	t.Add(t, new(big.Int).Mul(ba[3], bb[2]))
	t.Mul(t, W)
	r1.Add(r1, t)

	// r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
	r2 := new(big.Int).Mul(ba[0], bb[2])
	r2.Add(r2, new(big.Int).Mul(ba[1], bb[1]))
	r2.Add(r2, new(big.Int).Mul(ba[2], bb[0]))
	t = new(big.Int).Mul(ba[3], bb[3])
	t.Mul(t, W)
	r2.Add(r2, t)

	// r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
	r3 := new(big.Int).Mul(ba[0], bb[3])
	r3.Add(r3, new(big.Int).Mul(ba[1], bb[2]))
	r3.Add(r3, new(big.Int).Mul(ba[2], bb[1]))
	r3.Add(r3, new(big.Int).Mul(ba[3], bb[0]))

	return Ext4{modP(r0), modP(r1), modP(r2), modP(r3)}
}

func ext4Inv(a Ext4) Ext4 {
	// All arithmetic uses big.Int to avoid overflow.
	ba := [4]*big.Int{big.NewInt(int64(a[0])), big.NewInt(int64(a[1])), big.NewInt(int64(a[2])), big.NewInt(int64(a[3]))}

	// norm0 = a0^2 + W*a2^2 - 2*W*a1*a3
	norm0 := new(big.Int).Mul(ba[0], ba[0])
	t := new(big.Int).Mul(ba[2], ba[2])
	t.Mul(t, W)
	norm0.Add(norm0, t)
	t = new(big.Int).Mul(ba[1], ba[3])
	t.Mul(t, big.NewInt(2))
	t.Mul(t, W)
	norm0.Sub(norm0, t)
	norm0.Mod(norm0, P)
	if norm0.Sign() < 0 {
		norm0.Add(norm0, P)
	}

	// norm1 = 2*a0*a2 - a1^2 - W*a3^2
	norm1 := new(big.Int).Mul(ba[0], ba[2])
	norm1.Mul(norm1, big.NewInt(2))
	t = new(big.Int).Mul(ba[1], ba[1])
	norm1.Sub(norm1, t)
	t = new(big.Int).Mul(ba[3], ba[3])
	t.Mul(t, W)
	norm1.Sub(norm1, t)
	norm1.Mod(norm1, P)
	if norm1.Sign() < 0 {
		norm1.Add(norm1, P)
	}

	// det = norm0^2 - W*norm1^2
	det := new(big.Int).Mul(norm0, norm0)
	t = new(big.Int).Mul(norm1, norm1)
	t.Mul(t, W)
	det.Sub(det, t)
	det.Mod(det, P)
	if det.Sign() < 0 {
		det.Add(det, P)
	}

	// scalar = inv(det)
	scalar := new(big.Int).Exp(det, new(big.Int).Sub(P, big.NewInt(2)), P)

	// invN0 = norm0 * scalar mod p
	invN0 := new(big.Int).Mul(norm0, scalar)
	invN0.Mod(invN0, P)

	// invN1 = -norm1 * scalar mod p = (p - norm1) * scalar mod p
	negNorm1 := new(big.Int).Sub(P, norm1)
	negNorm1.Mod(negNorm1, P)
	invN1 := new(big.Int).Mul(negNorm1, scalar)
	invN1.Mod(invN1, P)

	// r0 = a0*invN0 + W*a2*invN1
	r0 := new(big.Int).Mul(ba[0], invN0)
	t = new(big.Int).Mul(ba[2], invN1)
	t.Mul(t, W)
	r0.Add(r0, t)

	// r1 = -(a1*invN0 + W*a3*invN1)
	r1 := new(big.Int).Mul(ba[1], invN0)
	t = new(big.Int).Mul(ba[3], invN1)
	t.Mul(t, W)
	r1.Add(r1, t)
	r1.Neg(r1)

	// r2 = a0*invN1 + a2*invN0
	r2 := new(big.Int).Mul(ba[0], invN1)
	t = new(big.Int).Mul(ba[2], invN0)
	r2.Add(r2, t)

	// r3 = -(a1*invN1 + a3*invN0)
	r3 := new(big.Int).Mul(ba[1], invN1)
	t = new(big.Int).Mul(ba[3], invN0)
	r3.Add(r3, t)
	r3.Neg(r3)

	return Ext4{modP(r0), modP(r1), modP(r2), modP(r3)}
}

// ─── JSON types ─────────────────────────────────────────────────────

type BaseVectorFile struct {
	Field   string       `json:"field"`
	Prime   uint64       `json:"prime"`
	Vectors []BaseVector `json:"vectors"`
}

type BaseVector struct {
	Op          string  `json:"op"`
	A           uint64  `json:"a"`
	B           *uint64 `json:"b,omitempty"`
	Expected    uint64  `json:"expected"`
	Description string  `json:"description"`
}

type Ext4VectorFile struct {
	Field           string       `json:"field"`
	Prime           uint64       `json:"prime"`
	ExtensionDegree int          `json:"extension_degree"`
	Vectors         []Ext4Vector `json:"vectors"`
}

type Ext4Vector struct {
	Op          string `json:"op"`
	A           Ext4   `json:"a"`
	B           *Ext4  `json:"b,omitempty"`
	Expected    Ext4   `json:"expected"`
	Description string `json:"description"`
}

// ─── Helper: pointer to uint64 ──────────────────────────────────────

func u64ptr(v uint64) *uint64 { return &v }

// ─── Helper: random field element ───────────────────────────────────

func randField(rng *rand.Rand) uint64 {
	return uint64(rng.Int63n(P.Int64()))
}

func randNonZeroField(rng *rand.Rand) uint64 {
	for {
		v := randField(rng)
		if v != 0 {
			return v
		}
	}
}

func randExt4(rng *rand.Rand) Ext4 {
	return Ext4{randField(rng), randField(rng), randField(rng), randField(rng)}
}

func randNonZeroExt4(rng *rand.Rand) Ext4 {
	for {
		e := randExt4(rng)
		if e != (Ext4{0, 0, 0, 0}) {
			return e
		}
	}
}

// ─── Constants ──────────────────────────────────────────────────────

var p = P.Uint64() // 2130706433

// ─── Generate add vectors ───────────────────────────────────────────

func generateAddVectors() []BaseVector {
	var vecs []BaseVector
	rng := rand.New(rand.NewSource(42))

	// Edge cases: zero
	vecs = append(vecs, BaseVector{"add", 0, u64ptr(0), fieldAdd(0, 0), "0 + 0 = 0"})
	vecs = append(vecs, BaseVector{"add", 1, u64ptr(0), fieldAdd(1, 0), "1 + 0 = 1 (additive identity)"})
	vecs = append(vecs, BaseVector{"add", 0, u64ptr(1), fieldAdd(0, 1), "0 + 1 = 1 (additive identity)"})

	// Edge cases: near prime
	vecs = append(vecs, BaseVector{"add", p - 1, u64ptr(1), fieldAdd(p-1, 1), "(p-1) + 1 = 0 (wrap around)"})
	vecs = append(vecs, BaseVector{"add", p - 1, u64ptr(p - 1), fieldAdd(p-1, p-1), "(p-1) + (p-1) = p-2 (double wrap)"})
	vecs = append(vecs, BaseVector{"add", p - 2, u64ptr(2), fieldAdd(p-2, 2), "(p-2) + 2 = 0"})

	// Small values
	for i := uint64(1); i <= 10; i++ {
		for j := uint64(1); j <= 10; j++ {
			vecs = append(vecs, BaseVector{
				"add", i, u64ptr(j), fieldAdd(i, j),
				fmt.Sprintf("%d + %d", i, j),
			})
		}
	}

	// Powers of 2
	for i := 0; i < 31; i++ {
		a := uint64(1) << i
		if a < p {
			vecs = append(vecs, BaseVector{
				"add", a, u64ptr(1), fieldAdd(a, 1),
				fmt.Sprintf("2^%d + 1", i),
			})
		}
	}

	// Random values (50 pairs = 100 values consumed)
	for i := 0; i < 50; i++ {
		a := randField(rng)
		b := randField(rng)
		vecs = append(vecs, BaseVector{
			"add", a, u64ptr(b), fieldAdd(a, b),
			fmt.Sprintf("random: %d + %d", a, b),
		})
	}

	return vecs
}

// ─── Generate sub vectors ───────────────────────────────────────────

func generateSubVectors() []BaseVector {
	var vecs []BaseVector
	rng := rand.New(rand.NewSource(43))

	// Edge cases
	vecs = append(vecs, BaseVector{"sub", 0, u64ptr(0), fieldSub(0, 0), "0 - 0 = 0"})
	vecs = append(vecs, BaseVector{"sub", 1, u64ptr(0), fieldSub(1, 0), "1 - 0 = 1"})
	vecs = append(vecs, BaseVector{"sub", 0, u64ptr(1), fieldSub(0, 1), "0 - 1 = p-1 (underflow wrap)"})
	vecs = append(vecs, BaseVector{"sub", 1, u64ptr(p - 1), fieldSub(1, p-1), "1 - (p-1) = 2 (underflow wrap)"})
	vecs = append(vecs, BaseVector{"sub", p - 1, u64ptr(p - 1), fieldSub(p-1, p-1), "(p-1) - (p-1) = 0"})

	// Small values
	for i := uint64(0); i <= 10; i++ {
		for j := uint64(0); j <= 10; j++ {
			vecs = append(vecs, BaseVector{
				"sub", i, u64ptr(j), fieldSub(i, j),
				fmt.Sprintf("%d - %d", i, j),
			})
		}
	}

	// Random values (100 pairs)
	for i := 0; i < 100; i++ {
		a := randField(rng)
		b := randField(rng)
		vecs = append(vecs, BaseVector{
			"sub", a, u64ptr(b), fieldSub(a, b),
			fmt.Sprintf("random: %d - %d", a, b),
		})
	}

	return vecs
}

// ─── Generate mul vectors ───────────────────────────────────────────

func generateMulVectors() []BaseVector {
	var vecs []BaseVector
	rng := rand.New(rand.NewSource(44))

	// Edge cases
	vecs = append(vecs, BaseVector{"mul", 0, u64ptr(0), fieldMul(0, 0), "0 * 0 = 0"})
	vecs = append(vecs, BaseVector{"mul", 1, u64ptr(0), fieldMul(1, 0), "1 * 0 = 0"})
	vecs = append(vecs, BaseVector{"mul", 0, u64ptr(1), fieldMul(0, 1), "0 * 1 = 0"})
	vecs = append(vecs, BaseVector{"mul", 1, u64ptr(1), fieldMul(1, 1), "1 * 1 = 1 (multiplicative identity)"})
	vecs = append(vecs, BaseVector{"mul", p - 1, u64ptr(p - 1), fieldMul(p-1, p-1), "(p-1) * (p-1) = 1 ((-1)*(-1)=1)"})
	vecs = append(vecs, BaseVector{"mul", p - 1, u64ptr(2), fieldMul(p-1, 2), "(p-1) * 2 = p-2 ((-1)*2=-2)"})

	// Small values
	for i := uint64(1); i <= 12; i++ {
		for j := uint64(1); j <= 12; j++ {
			vecs = append(vecs, BaseVector{
				"mul", i, u64ptr(j), fieldMul(i, j),
				fmt.Sprintf("%d * %d", i, j),
			})
		}
	}

	// Powers of 2
	for i := 0; i < 31; i++ {
		a := uint64(1) << i
		if a < p {
			vecs = append(vecs, BaseVector{
				"mul", a, u64ptr(2), fieldMul(a, 2),
				fmt.Sprintf("2^%d * 2", i),
			})
		}
	}

	// Large products that require reduction
	vecs = append(vecs, BaseVector{"mul", 123456, u64ptr(789012), fieldMul(123456, 789012), "123456 * 789012 (large product)"})
	vecs = append(vecs, BaseVector{"mul", 1000000000, u64ptr(1000000000), fieldMul(1000000000, 1000000000), "10^9 * 10^9 (overflow reduction)"})

	// Generator chain: KoalaBear has generator g = 3 for the multiplicative group
	gen := uint64(3)
	g := gen
	for i := 1; i <= 20; i++ {
		nextG := fieldMul(g, gen)
		vecs = append(vecs, BaseVector{
			"mul", g, u64ptr(gen), nextG,
			fmt.Sprintf("g^%d * g (generator chain)", i),
		})
		g = nextG
	}

	// Random values (50 pairs)
	for i := 0; i < 50; i++ {
		a := randField(rng)
		b := randField(rng)
		vecs = append(vecs, BaseVector{
			"mul", a, u64ptr(b), fieldMul(a, b),
			fmt.Sprintf("random: %d * %d", a, b),
		})
	}

	return vecs
}

// ─── Generate inv vectors ───────────────────────────────────────────

func generateInvVectors() []BaseVector {
	var vecs []BaseVector
	rng := rand.New(rand.NewSource(45))

	// Edge cases
	vecs = append(vecs, BaseVector{"inv", 1, nil, fieldInv(1), "inv(1) = 1"})
	vecs = append(vecs, BaseVector{"inv", p - 1, nil, fieldInv(p - 1), "inv(p-1) = p-1 (inv(-1) = -1)"})
	vecs = append(vecs, BaseVector{"inv", 2, nil, fieldInv(2), "inv(2)"})

	// Small values
	for i := uint64(1); i <= 50; i++ {
		vecs = append(vecs, BaseVector{
			"inv", i, nil, fieldInv(i),
			fmt.Sprintf("inv(%d)", i),
		})
	}

	// Powers of 2
	for i := 1; i < 31; i++ {
		a := uint64(1) << i
		if a < p {
			vecs = append(vecs, BaseVector{
				"inv", a, nil, fieldInv(a),
				fmt.Sprintf("inv(2^%d)", i),
			})
		}
	}

	// Near-prime values
	for offset := uint64(1); offset <= 10; offset++ {
		vecs = append(vecs, BaseVector{
			"inv", p - offset, nil, fieldInv(p - offset),
			fmt.Sprintf("inv(p-%d)", offset),
		})
	}

	// Generator powers
	gen := uint64(3)
	g := gen
	for i := 1; i <= 20; i++ {
		vecs = append(vecs, BaseVector{
			"inv", g, nil, fieldInv(g),
			fmt.Sprintf("inv(g^%d) where g=3", i),
		})
		g = fieldMul(g, gen)
	}

	// Random values (non-zero)
	for i := 0; i < 50; i++ {
		a := randNonZeroField(rng)
		inv := fieldInv(a)
		// Verify: a * inv(a) = 1
		check := fieldMul(a, inv)
		if check != 1 {
			panic(fmt.Sprintf("inv verification failed: %d * %d = %d (expected 1)", a, inv, check))
		}
		vecs = append(vecs, BaseVector{
			"inv", a, nil, inv,
			fmt.Sprintf("random: inv(%d)", a),
		})
	}

	return vecs
}

// ─── Generate ext4_mul vectors ──────────────────────────────────────

func generateExt4MulVectors() []Ext4Vector {
	var vecs []Ext4Vector
	rng := rand.New(rand.NewSource(46))

	one := Ext4{1, 0, 0, 0}
	zero := Ext4{0, 0, 0, 0}
	a := Ext4{42, 17, 99, 3}

	// Identity: a * 1 = a
	result := ext4Mul(a, one)
	vecs = append(vecs, Ext4Vector{"ext4_mul", a, &one, result, "a * 1 = a (multiplicative identity)"})

	// Zero: a * 0 = 0
	result = ext4Mul(a, zero)
	vecs = append(vecs, Ext4Vector{"ext4_mul", a, &zero, result, "a * 0 = 0"})

	// Base field embedding: (x,0,0,0) * (y,0,0,0) = (x*y mod p, 0, 0, 0)
	for i := uint64(1); i <= 10; i++ {
		for j := uint64(1); j <= 10; j++ {
			ea := Ext4{i, 0, 0, 0}
			eb := Ext4{j, 0, 0, 0}
			result = ext4Mul(ea, eb)
			vecs = append(vecs, Ext4Vector{
				"ext4_mul", ea, &eb, result,
				fmt.Sprintf("base: %d * %d", i, j),
			})
		}
	}

	// Pure extension elements: (0, a1, 0, 0) * (0, b1, 0, 0)
	for _, i := range []uint64{1, 2, 5, 100, p - 1} {
		for _, j := range []uint64{1, 3, 7, 200, p - 2} {
			ea := Ext4{0, i, 0, 0}
			eb := Ext4{0, j, 0, 0}
			result = ext4Mul(ea, eb)
			vecs = append(vecs, Ext4Vector{
				"ext4_mul", ea, &eb, result,
				fmt.Sprintf("pure ext: (0,%d,0,0) * (0,%d,0,0)", i, j),
			})
		}
	}

	// Mixed elements
	testElems := []Ext4{
		{1, 1, 0, 0},
		{1, 0, 1, 0},
		{1, 0, 0, 1},
		{1, 1, 1, 1},
		{p - 1, p - 1, p - 1, p - 1},
		{2, 3, 5, 7},
		{11, 13, 17, 19},
	}
	for _, ea := range testElems {
		for _, eb := range testElems {
			result = ext4Mul(ea, eb)
			vecs = append(vecs, Ext4Vector{
				"ext4_mul", ea, &eb, result,
				fmt.Sprintf("mixed: %v * %v", ea, eb),
			})
		}
	}

	// Random values (50 pairs)
	for i := 0; i < 50; i++ {
		ea := randExt4(rng)
		eb := randExt4(rng)
		result = ext4Mul(ea, eb)
		vecs = append(vecs, Ext4Vector{
			"ext4_mul", ea, &eb, result,
			fmt.Sprintf("random: %v * %v", ea, eb),
		})
	}

	return vecs
}

// ─── Generate ext4_inv vectors ──────────────────────────────────────

func generateExt4InvVectors() []Ext4Vector {
	var vecs []Ext4Vector
	rng := rand.New(rand.NewSource(47))

	one := Ext4{1, 0, 0, 0}

	// inv(1) = 1
	inv := ext4Inv(one)
	vecs = append(vecs, Ext4Vector{"ext4_inv", one, nil, inv, "inv(1) = 1"})

	// inv(-1) = -1
	negOne := Ext4{p - 1, 0, 0, 0}
	inv = ext4Inv(negOne)
	vecs = append(vecs, Ext4Vector{"ext4_inv", negOne, nil, inv, "inv(-1) = -1"})

	// Base field embeddings
	for _, i := range []uint64{2, 3, 5, 7, 11, 42, 100, p - 1, p - 2} {
		ea := Ext4{i, 0, 0, 0}
		inv = ext4Inv(ea)
		// Verify: a * inv(a) = 1
		check := ext4Mul(ea, inv)
		if check != one {
			panic(fmt.Sprintf("ext4 inv verification failed for base(%d): got %v", i, check))
		}
		vecs = append(vecs, Ext4Vector{
			"ext4_inv", ea, nil, inv,
			fmt.Sprintf("inv((%d,0,0,0))", i),
		})
	}

	// Pure extension elements and mixed
	testElems := []Ext4{
		{0, 1, 0, 0},
		{0, 0, 1, 0},
		{0, 0, 0, 1},
		{1, 1, 0, 0},
		{1, 1, 1, 1},
		{2, 3, 5, 7},
		{11, 13, 17, 19},
		{p - 1, p - 1, p - 1, p - 1},
	}
	for _, ea := range testElems {
		inv = ext4Inv(ea)
		// Verify: a * inv(a) = 1
		check := ext4Mul(ea, inv)
		if check != one {
			panic(fmt.Sprintf("ext4 inv verification failed for %v: got %v", ea, check))
		}
		vecs = append(vecs, Ext4Vector{
			"ext4_inv", ea, nil, inv,
			fmt.Sprintf("inv(%v)", ea),
		})
	}

	// Random values (non-zero), 50 vectors
	for i := 0; i < 50; i++ {
		ea := randNonZeroExt4(rng)
		inv = ext4Inv(ea)
		// Verify: a * inv(a) = 1
		check := ext4Mul(ea, inv)
		if check != one {
			panic(fmt.Sprintf("ext4 inv verification failed for random %v: got %v", ea, check))
		}
		vecs = append(vecs, Ext4Vector{
			"ext4_inv", ea, nil, inv,
			fmt.Sprintf("random: inv(%v)", ea),
		})
	}

	return vecs
}

// ─── Write JSON ─────────────────────────────────────────────────────

func writeJSON(path string, data interface{}) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0644); err != nil {
		panic(err)
	}
}

// ─── Main ───────────────────────────────────────────────────────────

func main() {
	// Determine output directory relative to this script's location
	vectorsDir := filepath.Join("..", "vectors")
	if err := os.MkdirAll(vectorsDir, 0755); err != nil {
		// Try absolute path fallback
		vectorsDir = filepath.Join(os.Getenv("HOME"), "gitcheckout", "runar", "tests", "vectors")
		if err := os.MkdirAll(vectorsDir, 0755); err != nil {
			panic(err)
		}
	}

	// Verify base field edge cases before generating
	if fieldAdd(p-1, 1) != 0 {
		panic("sanity check failed: (p-1)+1 != 0")
	}
	if fieldMul(p-1, p-1) != 1 {
		panic("sanity check failed: (p-1)*(p-1) != 1")
	}
	if fieldInv(1) != 1 {
		panic("sanity check failed: inv(1) != 1")
	}
	if fieldMul(2, fieldInv(2)) != 1 {
		panic("sanity check failed: 2*inv(2) != 1")
	}

	// Addition
	addVecs := generateAddVectors()
	writeJSON(filepath.Join(vectorsDir, "koalabear_add.json"), BaseVectorFile{
		Field: "koalabear", Prime: p, Vectors: addVecs,
	})
	fmt.Printf("Generated %d addition vectors\n", len(addVecs))

	// Subtraction
	subVecs := generateSubVectors()
	writeJSON(filepath.Join(vectorsDir, "koalabear_sub.json"), BaseVectorFile{
		Field: "koalabear", Prime: p, Vectors: subVecs,
	})
	fmt.Printf("Generated %d subtraction vectors\n", len(subVecs))

	// Multiplication
	mulVecs := generateMulVectors()
	writeJSON(filepath.Join(vectorsDir, "koalabear_mul.json"), BaseVectorFile{
		Field: "koalabear", Prime: p, Vectors: mulVecs,
	})
	fmt.Printf("Generated %d multiplication vectors\n", len(mulVecs))

	// Inverse
	invVecs := generateInvVectors()
	writeJSON(filepath.Join(vectorsDir, "koalabear_inv.json"), BaseVectorFile{
		Field: "koalabear", Prime: p, Vectors: invVecs,
	})
	fmt.Printf("Generated %d inverse vectors\n", len(invVecs))

	// Ext4 multiplication
	ext4MulVecs := generateExt4MulVectors()
	writeJSON(filepath.Join(vectorsDir, "koalabear_ext4_mul.json"), Ext4VectorFile{
		Field: "koalabear_ext4", Prime: p, ExtensionDegree: 4, Vectors: ext4MulVecs,
	})
	fmt.Printf("Generated %d ext4 multiplication vectors\n", len(ext4MulVecs))

	// Ext4 inverse
	ext4InvVecs := generateExt4InvVectors()
	writeJSON(filepath.Join(vectorsDir, "koalabear_ext4_inv.json"), Ext4VectorFile{
		Field: "koalabear_ext4", Prime: p, ExtensionDegree: 4, Vectors: ext4InvVecs,
	})
	fmt.Printf("Generated %d ext4 inverse vectors\n", len(ext4InvVecs))

	fmt.Printf("\nAll KoalaBear test vectors written to %s\n", vectorsDir)
}
