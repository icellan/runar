package codegen

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// F-196 -- the raw BN254 scalar-field builtins (bn254FieldAdd / Sub / Mul /
// Inv / Neg) took witness operands with no range check at all.
//
// R-119 gated the BabyBear and KoalaBear entry points; R-141 gated the BN254
// G1 POINT builtins' coordinates. The five scalar-field entry points in
// bn254.go got neither: EmitBN254FieldAdd went straight into OP_ADD and the
// bare-OP_MOD bn254FieldModPositive, whose own comment reads "SAFETY: Only use
// when the input is guaranteed non-negative". Nothing guaranteed it. OP_MOD
// takes the sign of the DIVIDEND, so measured on the go-sdk interpreter
// before this gate:
//
//	bn254FieldAdd(-1, 0) -> -1           bn254FieldAdd(p-1, 0) -> p-1
//	bn254FieldMul(-1, 1) -> -1           bn254FieldMul(p-1, 1) -> p-1
//
// two script numbers for one residue out of a builtin whose codomain is the
// field, and the `v + p` alias (bn254FieldAdd(p, 0) -> 0) accepted as a second
// spelling of 0.
//
// The gate is R-119's, per operand, on the public entry points only:
//
//	OP_PICK <0> <p> OP_WITHIN OP_VERIFY
//
// WHAT THIS PROVES: on the go-sdk interpreter, each of the five entry points
// ABORTS for an operand of -1, of exactly p, and of 5+p, in every operand
// position; and ACCEPTS canonical operands up to p-1 with a result checked
// against math/big, so an over-strict gate reddens too.
// WHAT IT DOES NOT PROVE: anything about the Groth16 / pairing paths, which
// call the INTERNAL bn254Field* helpers on values their own preambles
// validate, and are deliberately not gated here; nor the other tiers -- the
// cross-tier, compiled-contract leg on @bsv/sdk Spend is the F-196 block in
// conformance/go-only-parity/go-only-parity.test.ts.
// ---------------------------------------------------------------------------

func TestF196_BN254FieldNonCanonicalOperandRejected(t *testing.T) {
	p := bn254FieldP
	alias := new(big.Int).Add(bi(5), p)

	// The bug itself, stated as the accept it used to be: -1 came back as -1.
	if runField(t, EmitBN254FieldAdd, []*big.Int{bi(-1), bi(0)}, bi(-1)) {
		t.Errorf("bn254FieldAdd(-1, 0) returned -1 -- a value outside the field")
	}
	if runField(t, EmitBN254FieldMul, []*big.Int{bi(-1), bi(1)}, bi(-1)) {
		t.Errorf("bn254FieldMul(-1, 1) returned -1 -- a value outside the field")
	}

	type binCase struct {
		name string
		emit func(func(StackOp))
	}
	for _, c := range []binCase{
		{"add", EmitBN254FieldAdd}, {"sub", EmitBN254FieldSub}, {"mul", EmitBN254FieldMul},
	} {
		for _, bad := range []*big.Int{bi(-1), p, alias} {
			if runFieldRaw(t, c.emit, []*big.Int{bad, bi(0)}) {
				t.Errorf("bn254Field%s(%s, 0) accepted", c.name, bad)
			}
			if runFieldRaw(t, c.emit, []*big.Int{bi(1), bad}) {
				t.Errorf("bn254Field%s(1, %s) accepted", c.name, bad)
			}
		}
	}
	for _, c := range []binCase{{"inv", EmitBN254FieldInv}, {"neg", EmitBN254FieldNeg}} {
		for _, bad := range []*big.Int{bi(-1), p, alias} {
			if runFieldRaw(t, c.emit, []*big.Int{bad}) {
				t.Errorf("bn254Field%s(%s) accepted", c.name, bad)
			}
		}
	}
}

func TestF196_BN254FieldCanonicalOperandsNearPAccepted(t *testing.T) {
	p := bn254FieldP
	pm1 := new(big.Int).Sub(p, bi(1))
	pm2 := new(big.Int).Sub(p, bi(2))
	mod := func(v *big.Int) *big.Int { return new(big.Int).Mod(v, p) }

	bin := []struct {
		name string
		emit func(func(StackOp))
		a, b *big.Int
		want *big.Int
	}{
		{"add(p-1,p-1)", EmitBN254FieldAdd, pm1, pm1, mod(new(big.Int).Add(pm1, pm1))},
		{"add(p-1,1)", EmitBN254FieldAdd, pm1, bi(1), bi(0)},
		{"add(0,0)", EmitBN254FieldAdd, bi(0), bi(0), bi(0)},
		{"sub(0,p-1)", EmitBN254FieldSub, bi(0), pm1, bi(1)},
		{"sub(0,1)", EmitBN254FieldSub, bi(0), bi(1), pm1},
		{"mul(p-1,p-1)", EmitBN254FieldMul, pm1, pm1, bi(1)},
		{"mul(p-1,2)", EmitBN254FieldMul, pm1, bi(2), pm2},
	}
	for _, c := range bin {
		if !runField(t, c.emit, []*big.Int{c.a, c.b}, c.want) {
			t.Errorf("%s = %s rejected", c.name, c.want)
		}
	}

	inv2 := new(big.Int).ModInverse(bi(2), p)
	un := []struct {
		name string
		emit func(func(StackOp))
		a    *big.Int
		want *big.Int
	}{
		{"inv(p-1)", EmitBN254FieldInv, pm1, pm1},
		{"inv(2)", EmitBN254FieldInv, bi(2), inv2},
		{"neg(0)", EmitBN254FieldNeg, bi(0), bi(0)},
		{"neg(p-1)", EmitBN254FieldNeg, pm1, bi(1)},
		{"neg(1)", EmitBN254FieldNeg, bi(1), pm1},
	}
	for _, c := range un {
		if !runField(t, c.emit, []*big.Int{c.a}, c.want) {
			t.Errorf("%s = %s rejected", c.name, c.want)
		}
	}
}
