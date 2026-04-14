package codegen

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// Script-level correctness tests: compile to Bitcoin Script, execute in
// go-sdk interpreter, verify against reference vectors.
//
// These tests validate the CODEGEN path (StackOps → Bitcoin Script), not the
// Go runtime mock. The mocks are tested separately in packages/runar-go/.
//
// Note: these tests live in compilers/go/codegen (not integration/go) because
// they test internal codegen functions (EmitPoseidon2KBPermute, etc.) that are
// not exported as contract-level builtins. The go-sdk dependency is needed
// only for the script interpreter used to verify generated Bitcoin Script.
// ---------------------------------------------------------------------------

// buildAndExecute is a test-friendly wrapper around BuildAndExecuteOps that
// fails the test on emit errors and returns the script execution result.
// It exists so existing component tests in this package don't need to
// change while the public BuildAndExecuteOps becomes the canonical entry
// point for external test code.
func buildAndExecute(t *testing.T, ops []StackOp) error {
	t.Helper()
	return BuildAndExecuteOps(ops)
}

// pushBigInt creates a push StackOp for a big.Int value.
func pushBigInt(n *big.Int) StackOp {
	return StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(n)}}
}

// pushInt64 creates a push StackOp for an int64.
func pushInt64(n int64) StackOp {
	return StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(n)}}
}

func opcode(code string) StackOp {
	return StackOp{Op: "opcode", Code: code}
}

// gatherOps runs an emit function and collects the StackOps it produces.
func gatherOps(emitFn func(func(StackOp))) []StackOp {
	var ops []StackOp
	emitFn(func(op StackOp) { ops = append(ops, op) })
	return ops
}

// ---------------------------------------------------------------------------
// KoalaBear field arithmetic script tests
// ---------------------------------------------------------------------------

type kbVectorFile struct {
	Vectors []kbVector `json:"vectors"`
}

type kbVector struct {
	A        int64  `json:"a"`
	B        *int64 `json:"b,omitempty"`
	Expected int64  `json:"expected"`
	Desc     string `json:"description"`
}

func loadKBVectors(t *testing.T, filename string) []kbVector {
	data, err := os.ReadFile("../../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var f kbVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f.Vectors
}

// testKBBinaryOp tests a binary KoalaBear operation against vectors.
func testKBBinaryOp(t *testing.T, filename string, emitFn func(func(StackOp))) {
	vecs := loadKBVectors(t, filename)
	opOps := gatherOps(emitFn)

	for _, v := range vecs {
			t.Run(v.Desc, func(t *testing.T) {
			// Build script: push a, push b, <operation>, push expected, OP_EQUALVERIFY, OP_1
			var ops []StackOp
			ops = append(ops, pushInt64(v.A))
			ops = append(ops, pushInt64(*v.B))
			ops = append(ops, opOps...)
			ops = append(ops, pushInt64(v.Expected))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed: %v", err)
			}
		})
	}
}

func TestKBFieldAdd_Script(t *testing.T) {
	testKBBinaryOp(t, "koalabear_add.json", EmitKBFieldAdd)
}

func TestKBFieldSub_Script(t *testing.T) {
	testKBBinaryOp(t, "koalabear_sub.json", EmitKBFieldSub)
}

func TestKBFieldMul_Script(t *testing.T) {
	testKBBinaryOp(t, "koalabear_mul.json", EmitKBFieldMul)
}

// ---------------------------------------------------------------------------
// Poseidon2 KoalaBear script tests
// ---------------------------------------------------------------------------

type p2VectorFile struct {
	Vectors []p2Vector `json:"vectors"`
}

type p2Vector struct {
	Op       string  `json:"op"`
	Input    []int64 `json:"input,omitempty"`
	Left     []int64 `json:"left,omitempty"`
	Right    []int64 `json:"right,omitempty"`
	Expected []int64 `json:"expected"`
	Desc     string  `json:"description"`
}

func loadP2Vectors(t *testing.T) []p2Vector {
	data, err := os.ReadFile("../../../tests/vectors/poseidon2_koalabear.json")
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var f p2VectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f.Vectors
}

func TestPoseidon2KBPermute_Script(t *testing.T) {
	vecs := loadP2Vectors(t)
	permuteOps := gatherOps(EmitPoseidon2KBPermute)

	for _, v := range vecs {
		if v.Op != "permute" {
			continue
		}
		t.Run(v.Desc, func(t *testing.T) {
			var ops []StackOp

			// Push 16 input elements (s0 deepest, s15 on top)
			for _, val := range v.Input {
				ops = append(ops, pushInt64(val))
			}

			// Run the permutation
			ops = append(ops, permuteOps...)

			// Check outputs from top: s15 is on top, s0 is deepest.
			// Compare each output by popping from top and verifying.
			for i := 15; i >= 0; i-- {
				ops = append(ops, pushInt64(v.Expected[i]))
				ops = append(ops, opcode("OP_EQUALVERIFY"))
			}

			// Script must leave OP_TRUE (but stack is now empty after all EQUALVERIFYs)
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed: %v", err)
			}
		})
	}
}

func TestPoseidon2KBCompress_Script(t *testing.T) {
	vecs := loadP2Vectors(t)
	compressOps := gatherOps(EmitPoseidon2KBCompress)

	for _, v := range vecs {
		if v.Op != "compress" {
			continue
		}
		t.Run(v.Desc, func(t *testing.T) {
			var ops []StackOp

			// Push 16 input elements: left[0..7] then right[0..7]
			for _, val := range v.Left {
				ops = append(ops, pushInt64(val))
			}
			for _, val := range v.Right {
				ops = append(ops, pushInt64(val))
			}

			// Run compression (produces 8 elements: h0 deepest, h7 on top)
			ops = append(ops, compressOps...)

			// Check 8 outputs from top
			for i := 7; i >= 0; i-- {
				ops = append(ops, pushInt64(v.Expected[i]))
				ops = append(ops, opcode("OP_EQUALVERIFY"))
			}

			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// KoalaBear field arithmetic script tests (continued)
// ---------------------------------------------------------------------------

func TestKBFieldInv_Script(t *testing.T) {
	vecs := loadKBVectors(t, "koalabear_inv.json")
	opOps := gatherOps(EmitKBFieldInv)

	for _, v := range vecs {
			t.Run(v.Desc, func(t *testing.T) {
			var ops []StackOp
			ops = append(ops, pushInt64(v.A))
			ops = append(ops, opOps...)
			ops = append(ops, pushInt64(v.Expected))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// KoalaBear ext4 script tests
// ---------------------------------------------------------------------------

type kbExt4VectorFile struct {
	Vectors []kbExt4Vector `json:"vectors"`
}

type kbExt4Vector struct {
	A    [4]int64  `json:"a"`
	B    *[4]int64 `json:"b,omitempty"`
	Exp  [4]int64  `json:"expected"`
	Desc string    `json:"description"`
}

func loadKBExt4Vectors(t *testing.T, filename string) []kbExt4Vector {
	data, err := os.ReadFile("../../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var f kbExt4VectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f.Vectors
}

func TestKBExt4Mul_Script(t *testing.T) {
	vecs := loadKBExt4Vectors(t, "koalabear_ext4_mul.json")

	mul0Ops := gatherOps(EmitKBExt4Mul0)
	mul1Ops := gatherOps(EmitKBExt4Mul1)
	mul2Ops := gatherOps(EmitKBExt4Mul2)
	mul3Ops := gatherOps(EmitKBExt4Mul3)

	for _, v := range vecs {
			t.Run(v.Desc, func(t *testing.T) {
			b := v.B
			for comp, compOps := range [][]StackOp{mul0Ops, mul1Ops, mul2Ops, mul3Ops} {
				var ops []StackOp
				for _, val := range v.A {
					ops = append(ops, pushInt64(val))
				}
				for _, val := range b {
					ops = append(ops, pushInt64(val))
				}
				ops = append(ops, compOps...)
				ops = append(ops, pushInt64(v.Exp[comp]))
				ops = append(ops, opcode("OP_EQUALVERIFY"))
				ops = append(ops, opcode("OP_1"))

				if err := buildAndExecute(t, ops); err != nil {
					t.Errorf("component %d failed: %v", comp, err)
				}
			}
		})
	}
}

func TestKBExt4Inv_Script(t *testing.T) {
	vecs := loadKBExt4Vectors(t, "koalabear_ext4_inv.json")

	inv0Ops := gatherOps(EmitKBExt4Inv0)
	inv1Ops := gatherOps(EmitKBExt4Inv1)
	inv2Ops := gatherOps(EmitKBExt4Inv2)
	inv3Ops := gatherOps(EmitKBExt4Inv3)

	for _, v := range vecs {
			t.Run(v.Desc, func(t *testing.T) {
			for comp, compOps := range [][]StackOp{inv0Ops, inv1Ops, inv2Ops, inv3Ops} {
				var ops []StackOp
				for _, val := range v.A {
					ops = append(ops, pushInt64(val))
				}
				ops = append(ops, compOps...)
				ops = append(ops, pushInt64(v.Exp[comp]))
				ops = append(ops, opcode("OP_EQUALVERIFY"))
				ops = append(ops, opcode("OP_1"))

				if err := buildAndExecute(t, ops); err != nil {
					t.Errorf("component %d failed: %v", comp, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BN254 field arithmetic script tests
// ---------------------------------------------------------------------------

type bn254VectorFile struct {
	Vectors []bn254Vector `json:"vectors"`
}

type bn254Vector struct {
	A    string  `json:"a"`
	B    *string `json:"b,omitempty"`
	Exp  string  `json:"expected"`
	Desc string  `json:"description"`
}

func loadBN254Vectors(t *testing.T, filename string) []bn254Vector {
	data, err := os.ReadFile("../../../tests/vectors/" + filename)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var f bn254VectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("no vectors loaded from %s", filename)
	}
	return f.Vectors
}

func hexToBigInt(h string) *big.Int {
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("hexToBigInt: invalid hex: " + h)
	}
	return n
}

func testBN254BinaryOp(t *testing.T, filename string, emitFn func(func(StackOp))) {
	vecs := loadBN254Vectors(t, filename)
	opOps := gatherOps(emitFn)

	for _, v := range vecs {
			t.Run(v.Desc, func(t *testing.T) {
			var ops []StackOp
			ops = append(ops, pushBigInt(hexToBigInt(v.A)))
			ops = append(ops, pushBigInt(hexToBigInt(*v.B)))
			ops = append(ops, opOps...)
			ops = append(ops, pushBigInt(hexToBigInt(v.Exp)))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BN254 Fp2 arithmetic script tests
// ---------------------------------------------------------------------------

// emitFp2Mul collects the StackOps for an Fp2 multiplication.
// Stack in:  [..., a0, a1, b0, b1] (b1 on top)
// Stack out: [..., r0, r1]
func emitFp2Mul(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a0", "a1", "b0", "b1"}, emit)
	t.PushPrimeCache()
	bn254Fp2Mul(t, "a0", "a1", "b0", "b1", "r0", "r1")
	t.PopPrimeCache()
}

func TestBN254Fp2Mul_Script(t *testing.T) {
	p := new(big.Int)
	p.SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	testCases := []struct {
		a0, a1, b0, b1 *big.Int
		desc           string
	}{
		// Zero * anything = 0
		{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(2), "zero_times_nonzero"},
		// Identity: (1,0) * (x,y) = (x,y)
		{big.NewInt(1), big.NewInt(0), big.NewInt(42), big.NewInt(17), "identity"},
		// Pure imaginary: (0,1) * (0,1) = (-1, 0) since u^2 = -1
		{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1), "i_squared"},
		// Max values: (p-1, p-1) * (p-1, p-1)
		{new(big.Int).Set(pMinus1), new(big.Int).Set(pMinus1),
			new(big.Int).Set(pMinus1), new(big.Int).Set(pMinus1), "max_values"},
		// Negative intermediate: a0*b0 < a1*b1
		{big.NewInt(1), new(big.Int).Set(pMinus1),
			big.NewInt(1), big.NewInt(1), "negative_intermediate"},
		// Small values
		{big.NewInt(3), big.NewInt(5), big.NewInt(7), big.NewInt(11), "small_values"},
		// One imaginary component zero
		{big.NewInt(100), big.NewInt(0), big.NewInt(200), big.NewInt(300), "a1_zero"},
	}

	fp2MulOps := gatherOps(emitFp2Mul)

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// Compute reference result with math/big:
			// r0 = (a0*b0 - a1*b1) mod p
			// r1 = (a0*b1 + a1*b0) mod p
			a0b0 := new(big.Int).Mul(tc.a0, tc.b0)
			a1b1 := new(big.Int).Mul(tc.a1, tc.b1)
			expR0 := new(big.Int).Sub(a0b0, a1b1)
			expR0.Mod(expR0, p)

			a0b1 := new(big.Int).Mul(tc.a0, tc.b1)
			a1b0 := new(big.Int).Mul(tc.a1, tc.b0)
			expR1 := new(big.Int).Add(a0b1, a1b0)
			expR1.Mod(expR1, p)

			// Build script: push a0, a1, b0, b1, run Fp2Mul, check r1 (on top), check r0
			var ops []StackOp
			ops = append(ops, pushBigInt(tc.a0))
			ops = append(ops, pushBigInt(tc.a1))
			ops = append(ops, pushBigInt(tc.b0))
			ops = append(ops, pushBigInt(tc.b1))
			ops = append(ops, fp2MulOps...)
			// r1 is on top, r0 is below
			ops = append(ops, pushBigInt(expR1))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, pushBigInt(expR0))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed for %s: %v (expected r0=%s, r1=%s)", tc.desc, err, expR0, expR1)
			}
		})
	}
}

// emitFp2Sqr collects the StackOps for an Fp2 squaring.
// Stack in:  [..., a0, a1] (a1 on top)
// Stack out: [..., r0, r1]
func emitFp2Sqr(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a0", "a1"}, emit)
	t.PushPrimeCache()
	bn254Fp2Sqr(t, "a0", "a1", "r0", "r1")
	t.PopPrimeCache()
}

func TestBN254Fp2Sqr_Script(t *testing.T) {
	p := new(big.Int)
	p.SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	testCases := []struct {
		a0, a1 *big.Int
		desc   string
	}{
		{big.NewInt(0), big.NewInt(0), "zero"},
		{big.NewInt(1), big.NewInt(0), "one"},
		{big.NewInt(0), big.NewInt(1), "i"},
		{big.NewInt(3), big.NewInt(5), "small"},
		{new(big.Int).Set(pMinus1), new(big.Int).Set(pMinus1), "max"},
		{big.NewInt(1), new(big.Int).Set(pMinus1), "negative_intermediate"},
	}

	fp2SqrOps := gatherOps(emitFp2Sqr)

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// Reference: (a0+a1*u)^2 = (a0^2 - a1^2) + 2*a0*a1*u
			a0sq := new(big.Int).Mul(tc.a0, tc.a0)
			a1sq := new(big.Int).Mul(tc.a1, tc.a1)
			expR0 := new(big.Int).Sub(a0sq, a1sq)
			expR0.Mod(expR0, p)

			expR1 := new(big.Int).Mul(tc.a0, tc.a1)
			expR1.Mul(expR1, big.NewInt(2))
			expR1.Mod(expR1, p)

			var ops []StackOp
			ops = append(ops, pushBigInt(tc.a0))
			ops = append(ops, pushBigInt(tc.a1))
			ops = append(ops, fp2SqrOps...)
			ops = append(ops, pushBigInt(expR1))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, pushBigInt(expR0))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed for %s: %v (expected r0=%s, r1=%s)", tc.desc, err, expR0, expR1)
			}
		})
	}
}

func TestBN254FieldAdd_Script(t *testing.T) {
	testBN254BinaryOp(t, "bn254_fp_add.json", EmitBN254FieldAdd)
}

func TestBN254FieldSub_Script(t *testing.T) {
	testBN254BinaryOp(t, "bn254_fp_sub.json", EmitBN254FieldSub)
}

func TestBN254FieldMul_Script(t *testing.T) {
	testBN254BinaryOp(t, "bn254_fp_mul.json", EmitBN254FieldMul)
}

func TestBN254FieldInv_Script(t *testing.T) {
	vecs := loadBN254Vectors(t, "bn254_fp_inv.json")
	opOps := gatherOps(EmitBN254FieldInv)

	for _, v := range vecs {
			t.Run(v.Desc, func(t *testing.T) {
			var ops []StackOp
			ops = append(ops, pushBigInt(hexToBigInt(v.A)))
			ops = append(ops, opOps...)
			ops = append(ops, pushBigInt(hexToBigInt(v.Exp)))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("script failed: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// KoalaBear negative tests — wrong expected values MUST cause script failure
// ---------------------------------------------------------------------------

func TestKBFieldAdd_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitKBFieldAdd)
	// a=3, b=7 => correct result is 10; push 11 (wrong)
	var ops []StackOp
	ops = append(ops, pushInt64(3))
	ops = append(ops, pushInt64(7))
	ops = append(ops, opOps...)
	ops = append(ops, pushInt64(11)) // wrong: should be 10
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

func TestKBFieldMul_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitKBFieldMul)
	// a=3, b=7 => correct result is 21; push 22 (wrong)
	var ops []StackOp
	ops = append(ops, pushInt64(3))
	ops = append(ops, pushInt64(7))
	ops = append(ops, opOps...)
	ops = append(ops, pushInt64(22)) // wrong: should be 21
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

func TestKBFieldInv_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitKBFieldInv)
	// a=2, correct inverse is (p+1)/2 = 1065353217; push 0 (wrong)
	var ops []StackOp
	ops = append(ops, pushInt64(2))
	ops = append(ops, opOps...)
	ops = append(ops, pushInt64(0)) // wrong
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

func TestKBFieldSub_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitKBFieldSub)
	// a=10, b=3 => correct result is 7; push 8 (wrong)
	var ops []StackOp
	ops = append(ops, pushInt64(10))
	ops = append(ops, pushInt64(3))
	ops = append(ops, opOps...)
	ops = append(ops, pushInt64(8)) // wrong: should be 7
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// BN254 negative tests — wrong expected values MUST cause script failure
// ---------------------------------------------------------------------------

func TestBN254FieldAdd_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitBN254FieldAdd)
	a := big.NewInt(42)
	b := big.NewInt(58)
	// correct: 100; wrong: 101
	var ops []StackOp
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(b))
	ops = append(ops, opOps...)
	ops = append(ops, pushBigInt(big.NewInt(101))) // wrong
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

func TestBN254FieldMul_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitBN254FieldMul)
	a := big.NewInt(7)
	b := big.NewInt(13)
	// correct: 91; wrong: 92
	var ops []StackOp
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(b))
	ops = append(ops, opOps...)
	ops = append(ops, pushBigInt(big.NewInt(92))) // wrong
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

func TestBN254FieldInv_Script_WrongResult(t *testing.T) {
	opOps := gatherOps(EmitBN254FieldInv)
	a := big.NewInt(7)
	// correct inverse of 7 mod p is some large number; wrong: 0
	var ops []StackOp
	ops = append(ops, pushBigInt(a))
	ops = append(ops, opOps...)
	ops = append(ops, pushBigInt(big.NewInt(0))) // wrong
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong expected value, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Poseidon2 negative tests — wrong expected output MUST cause script failure
// ---------------------------------------------------------------------------

func TestPoseidon2KBPermute_Script_WrongResult(t *testing.T) {
	permuteOps := gatherOps(EmitPoseidon2KBPermute)

	// All-zero input: known correct output from vectors file.
	// We flip the first expected element to verify the script rejects it.
	var ops []StackOp
	for i := 0; i < 16; i++ {
		ops = append(ops, pushInt64(0))
	}
	ops = append(ops, permuteOps...)

	// Known correct output for all-zero input (from poseidon2_koalabear.json)
	expected := [16]int64{
		1467453764, 68262570, 2085334433, 1711169726,
		869537427, 698494029, 1998923102, 727938840,
		1236421175, 857433239, 1995651691, 1526804549,
		968729910, 15322618, 1511105384, 1900792116,
	}

	// Tamper with the last element (on top) — use wrong value
	for i := 15; i >= 0; i-- {
		val := expected[i]
		if i == 15 {
			val = 999999 // wrong value for element 15
		}
		ops = append(ops, pushInt64(val))
		ops = append(ops, opcode("OP_EQUALVERIFY"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong Poseidon2 output, but it succeeded")
	}
}

func TestPoseidon2KBCompress_Script_WrongResult(t *testing.T) {
	compressOps := gatherOps(EmitPoseidon2KBCompress)

	// Both-zero compress case from vectors file
	var ops []StackOp
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(0))
	}
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(0))
	}
	ops = append(ops, compressOps...)

	// Load the correct expected for both-zero compress
	vecs := loadP2Vectors(t)
	var expected []int64
	for _, v := range vecs {
		if v.Op == "compress" && v.Desc == "both zero" {
			expected = v.Expected
			break
		}
	}
	if expected == nil {
		t.Fatal("could not find 'both zero' compress vector")
	}

	// Tamper with element 0 (deepest, checked last)
	for i := 7; i >= 0; i-- {
		val := expected[i]
		if i == 0 {
			val = 12345 // wrong value
		}
		ops = append(ops, pushInt64(val))
		ops = append(ops, opcode("OP_EQUALVERIFY"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong Poseidon2 compress output, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Fiat-Shamir script-level test — exercise sponge codegen via go-sdk
// ---------------------------------------------------------------------------

func TestFiatShamirKB_Observe_Script(t *testing.T) {
	// Verify the Fiat-Shamir sponge codegen produces correct Bitcoin Script by
	// running the full sponge lifecycle (init → 8 observes → squeeze) and
	// comparing the squeezed value against a reference computed by a direct
	// Poseidon2 permutation of the same absorbed state.
	//
	// The sponge absorbs elements 1..8 into rate slots fs0..fs7 (replacing the
	// initial zeros). The 8th observe fills the rate and triggers a permutation
	// of [1,2,3,4,5,6,7,8, 0,0,0,0,0,0,0,0]. The squeeze then reads fs0
	// from the post-permutation state.
	//
	// The reference is a direct permutation of the same 16-element state,
	// extracting element 0. Both computations run in the same Bitcoin Script
	// and the results are compared via OP_EQUALVERIFY.

	// Phase 1: Build the sponge tracker ops (self-contained, starts from empty stack).
	fs := NewFiatShamirState()
	var spongeOps []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) {
		spongeOps = append(spongeOps, op)
	})

	fs.EmitInit(tracker)
	for i := 0; i < 8; i++ {
		tracker.pushInt("element", int64(i+1))
		fs.EmitObserve(tracker)
	}
	fs.EmitSqueeze(tracker)

	// After the sponge ops, the stack (from the tracker's perspective) is:
	//   [fs0, fs1, ..., fs15, _fs_squeezed]
	// Total: 17 elements. The squeezed value is on top.

	// Phase 2: Build the verification script.
	// First run the sponge ops. Then compute the reference via direct permutation
	// on TOP of the sponge result stack. Finally compare.
	var ops []StackOp
	ops = append(ops, spongeOps...)

	// Now: stack = [fs0, ..., fs15, squeezed]
	// Compute reference: push [1..8, 0..0] and permute
	permuteOps := gatherOps(EmitPoseidon2KBPermute)
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(int64(i+1)))
	}
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(0))
	}
	ops = append(ops, permuteOps...)

	// Now: stack = [fs0, ..., fs15, squeezed, p2s0, p2s1, ..., p2s15]
	// We want p2s0 (element 0 = deepest of the 16 permutation results).
	// Drop the top 15 elements (p2s1..p2s15) to expose p2s0.
	for i := 0; i < 15; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}

	// Now: stack = [fs0, ..., fs15, squeezed, p2s0_ref]
	// Compare squeezed (at depth 1) with p2s0_ref (on top).
	ops = append(ops, opcode("OP_SWAP"))
	ops = append(ops, opcode("OP_EQUALVERIFY"))

	// Clean up the 16 sponge state elements.
	for i := 0; i < 16; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("Fiat-Shamir sponge script failed: %v", err)
	}
}

func TestFiatShamirKB_SqueezeExt4_Script(t *testing.T) {
	// Verify SqueezeExt4 produces 4 correct values through Bitcoin Script VM.
	// Build sponge: init → observe 8 elements → squeezeExt4.
	// Reference: direct Poseidon2 permutation of the same state, extract first 4.
	// Both run in the same script and results are compared via OP_EQUALVERIFY.
	//
	// NOTE: This test validates sponge ORCHESTRATION (squeeze position tracking,
	// rate handling), not Poseidon2 correctness. The reference uses the same
	// EmitPoseidon2KBPermute codegen — a systematic Poseidon2 bug would be
	// invisible here. Poseidon2 correctness is tested separately against
	// Plonky3 vectors in TestPoseidon2KBPermute_Script.

	fs := NewFiatShamirState()
	var spongeOps []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) {
		spongeOps = append(spongeOps, op)
	})

	fs.EmitInit(tracker)
	for i := 0; i < 8; i++ {
		tracker.pushInt("element", int64(i+1))
		fs.EmitObserve(tracker)
	}
	fs.EmitSqueezeExt4(tracker)

	// Stack: [fs0, ..., fs15, ext4_0, ext4_1, ext4_2, ext4_3]

	var ops []StackOp
	ops = append(ops, spongeOps...)

	// Compute reference: push [1..8, 0..0] and permute
	permuteOps := gatherOps(EmitPoseidon2KBPermute)
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(int64(i+1)))
	}
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(0))
	}
	ops = append(ops, permuteOps...)

	// Stack: [..., ext4_0..ext4_3, ref0..ref15]
	// Drop top 12 (ref4..ref15) to expose ref0..ref3.
	for i := 0; i < 12; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}

	// Stack: [..., ext4_0, ext4_1, ext4_2, ext4_3, ref0, ref1, ref2, ref3]
	// Compare pairs: roll depth decreases as pairs are consumed.
	// i=3: ref3 on top, ext4_3 at depth 4 → ROLL(4), EQUALVERIFY
	// i=2: ref2 on top, ext4_2 at depth 3 → ROLL(3), EQUALVERIFY
	// i=1: ref1 on top, ext4_1 at depth 2 → ROLL(2), EQUALVERIFY
	// i=0: ref0 on top, ext4_0 at depth 1 → SWAP, EQUALVERIFY
	for i := 3; i >= 0; i-- {
		depth := int64(i + 1)
		if depth == 1 {
			ops = append(ops, opcode("OP_SWAP"))
		} else {
			ops = append(ops, pushInt64(depth))
			ops = append(ops, opcode("OP_ROLL"))
		}
		ops = append(ops, opcode("OP_EQUALVERIFY"))
	}

	// Clean up 16 sponge state elements.
	for i := 0; i < 16; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("Fiat-Shamir SqueezeExt4 script failed: %v", err)
	}
}

func TestFiatShamirKB_SampleBits_Script(t *testing.T) {
	// Verify SampleBits produces correct bit-masked output through Bitcoin Script VM.
	// Build sponge: init → observe 8 elements → sampleBits(8).
	// Reference: direct Poseidon2 permutation, extract element 0, then mod 256.
	// Both run in the same script and results are compared via OP_EQUALVERIFY.
	//
	// NOTE: Tests sponge orchestration + bit masking, not Poseidon2 correctness.
	// See TestPoseidon2KBPermute_Script for Poseidon2 vector validation.

	fs := NewFiatShamirState()
	var spongeOps []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) {
		spongeOps = append(spongeOps, op)
	})

	fs.EmitInit(tracker)
	for i := 0; i < 8; i++ {
		tracker.pushInt("element", int64(i+1))
		fs.EmitObserve(tracker)
	}
	fs.EmitSampleBits(tracker, 8)

	// Stack: [fs0, ..., fs15, _fs_bits]
	// _fs_bits = permuted_state[0] % 256

	var ops []StackOp
	ops = append(ops, spongeOps...)

	// Compute reference: push [1..8, 0..0], permute, extract element 0, mod 256
	permuteOps := gatherOps(EmitPoseidon2KBPermute)
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(int64(i+1)))
	}
	for i := 0; i < 8; i++ {
		ops = append(ops, pushInt64(0))
	}
	ops = append(ops, permuteOps...)

	// Drop top 15 to expose p2s0
	for i := 0; i < 15; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}

	// Now: stack = [fs0..fs15, _fs_bits, p2s0_ref]
	// Apply same mask: p2s0 % 256
	ops = append(ops, pushInt64(256))
	ops = append(ops, opcode("OP_MOD"))

	// Compare _fs_bits (at depth 1) with masked p2s0 (on top)
	ops = append(ops, opcode("OP_SWAP"))
	ops = append(ops, opcode("OP_EQUALVERIFY"))

	// Clean up sponge state
	for i := 0; i < 16; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("Fiat-Shamir SampleBits script failed: %v", err)
	}
}

func TestFiatShamirKB_SqueezeRateExhaustion_Script(t *testing.T) {
	// Verify that the 9th consecutive squeeze (which triggers a second permutation
	// after rate exhaustion) produces the correct value through Bitcoin Script VM.
	//
	// The first 8 squeezes are from permute(zeros). The 9th squeeze triggers a new
	// permutation of the already-permuted state, reading element 0 of the result.
	//
	// We verify sq_8 by building a reference: permute(permute(zeros))[0].
	//
	// NOTE: Tests rate exhaustion logic (squeezePos >= RATE triggers re-permute),
	// not Poseidon2 correctness. See TestPoseidon2KBPermute_Script for vector tests.

	// Build a reference for squeeze 0 from permute(zeros)[0] — this is already
	// tested by TestFiatShamirKB_Observe_Script, so we just need sq_8.
	fs := NewFiatShamirState()
	var spongeOps []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) {
		spongeOps = append(spongeOps, op)
	})

	fs.EmitInit(tracker)
	// Squeeze 9 times. Only the 9th (sq_8) is verified here.
	for i := 0; i < 9; i++ {
		fs.EmitSqueeze(tracker)
		if i < 8 {
			// Consume intermediate squeeze values to keep the stack clean.
			tracker.drop()
		}
		// Last squeeze result (_fs_squeezed) stays on top.
	}

	// Stack: [fs0..fs15, _fs_squeezed]
	// _fs_squeezed = permute(permute(zeros))[0]

	var ops []StackOp
	ops = append(ops, spongeOps...)

	// Reference: push zeros → permute → permute → extract element 0
	permuteOps := gatherOps(EmitPoseidon2KBPermute)
	for i := 0; i < 16; i++ {
		ops = append(ops, pushInt64(0))
	}
	ops = append(ops, permuteOps...)
	ops = append(ops, permuteOps...)
	for i := 0; i < 15; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}

	// Stack: [fs0..fs15, _fs_squeezed, ref_double_perm_0]
	ops = append(ops, opcode("OP_SWAP"))
	ops = append(ops, opcode("OP_EQUALVERIFY"))

	// Clean up sponge state
	for i := 0; i < 16; i++ {
		ops = append(ops, opcode("OP_DROP"))
	}
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("Fiat-Shamir squeeze rate exhaustion script failed: %v", err)
	}
}
