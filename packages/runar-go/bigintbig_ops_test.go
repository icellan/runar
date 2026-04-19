package runar

import (
	"math/big"
	"testing"
)

// TestBigintBigComparisonHelpers covers the six BigintBig comparison
// helpers under the three ordering regimes (less, equal, greater). They
// exist so that DSL Go contracts can express `a < b` / `a == b` on
// *big.Int operands — Go's own comparison operators either reject the
// expression at compile time (`<`) or implement pointer identity (`==`),
// neither of which matches the Script-side OP_LESSTHAN / OP_NUMEQUAL
// semantics.
func TestBigintBigComparisonHelpers(t *testing.T) {
	type row struct {
		a, b *big.Int
		less bool
		leq  bool
		gt   bool
		geq  bool
		eq   bool
		neq  bool
	}

	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	// 2^300 — well outside int64 range, exercises the arbitrary-precision
	// path rather than something that could fit in a regular comparison.
	big1 := new(big.Int).Lsh(one, 300)
	big2 := new(big.Int).Add(big1, one)

	rows := []row{
		{a: zero, b: zero, less: false, leq: true, gt: false, geq: true, eq: true, neq: false},
		{a: one, b: two, less: true, leq: true, gt: false, geq: false, eq: false, neq: true},
		{a: two, b: one, less: false, leq: false, gt: true, geq: true, eq: false, neq: true},
		{a: big1, b: big2, less: true, leq: true, gt: false, geq: false, eq: false, neq: true},
		{a: big2, b: big1, less: false, leq: false, gt: true, geq: true, eq: false, neq: true},
		{a: new(big.Int).Set(big1), b: new(big.Int).Set(big1), less: false, leq: true, gt: false, geq: true, eq: true, neq: false},
		// nil should collapse to zero rather than panic (pointer-nil is a
		// realistic accident for BigintBig authors).
		{a: nil, b: zero, less: false, leq: true, gt: false, geq: true, eq: true, neq: false},
		{a: nil, b: one, less: true, leq: true, gt: false, geq: false, eq: false, neq: true},
	}

	for i, r := range rows {
		if got := BigintBigLess(r.a, r.b); got != r.less {
			t.Errorf("row %d: BigintBigLess(%v,%v) = %v, want %v", i, r.a, r.b, got, r.less)
		}
		if got := BigintBigLessEq(r.a, r.b); got != r.leq {
			t.Errorf("row %d: BigintBigLessEq(%v,%v) = %v, want %v", i, r.a, r.b, got, r.leq)
		}
		if got := BigintBigGreater(r.a, r.b); got != r.gt {
			t.Errorf("row %d: BigintBigGreater(%v,%v) = %v, want %v", i, r.a, r.b, got, r.gt)
		}
		if got := BigintBigGreaterEq(r.a, r.b); got != r.geq {
			t.Errorf("row %d: BigintBigGreaterEq(%v,%v) = %v, want %v", i, r.a, r.b, got, r.geq)
		}
		if got := BigintBigEqual(r.a, r.b); got != r.eq {
			t.Errorf("row %d: BigintBigEqual(%v,%v) = %v, want %v", i, r.a, r.b, got, r.eq)
		}
		if got := BigintBigNotEqual(r.a, r.b); got != r.neq {
			t.Errorf("row %d: BigintBigNotEqual(%v,%v) = %v, want %v", i, r.a, r.b, got, r.neq)
		}
	}
}

// TestBigintBigEqualValueSemantics pins the value-equality contract: two
// distinct *big.Int pointers with the same numeric value must compare
// equal. Plain Go `==` on *big.Int would be pointer identity and return
// false for this case — the whole point of the helper is to paper over
// that footgun.
func TestBigintBigEqualValueSemantics(t *testing.T) {
	a := new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03, 0x04})
	b := new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03, 0x04})
	if a == b {
		t.Fatal("precondition: distinct pointers expected")
	}
	if !BigintBigEqual(a, b) {
		t.Fatalf("BigintBigEqual on distinct pointers with same value should be true")
	}
}

// TestBigintBigArithmeticHelpers exercises Add/Sub/Mul/Mod/Div against
// reference *big.Int results, including wide (>2^300) operands and the
// truncated-semantics edge cases for Mod/Div that mirror Script's OP_MOD
// and OP_DIV.
func TestBigintBigArithmeticHelpers(t *testing.T) {
	a := new(big.Int).Lsh(big.NewInt(1), 300)  // 2^300
	b := new(big.Int).Lsh(big.NewInt(7), 200)  // 7 * 2^200
	neg := new(big.Int).Neg(big.NewInt(11))    // -11
	three := big.NewInt(3)
	five := big.NewInt(5)

	if got, want := BigintBigAdd(a, b), new(big.Int).Add(a, b); got.Cmp(want) != 0 {
		t.Errorf("Add mismatch: got %s want %s", got, want)
	}
	if got, want := BigintBigSub(a, b), new(big.Int).Sub(a, b); got.Cmp(want) != 0 {
		t.Errorf("Sub mismatch: got %s want %s", got, want)
	}
	if got, want := BigintBigMul(a, b), new(big.Int).Mul(a, b); got.Cmp(want) != 0 {
		t.Errorf("Mul mismatch: got %s want %s", got, want)
	}

	// Mod/Div use truncated semantics (Go's /, %), matching Script.
	for _, pair := range []struct{ x, y, modWant, divWant *big.Int }{
		{x: big.NewInt(17), y: five, modWant: big.NewInt(2), divWant: big.NewInt(3)},
		{x: neg, y: three, modWant: big.NewInt(-2), divWant: big.NewInt(-3)},
		{x: big.NewInt(0), y: five, modWant: big.NewInt(0), divWant: big.NewInt(0)},
		// Divide-by-zero returns 0 rather than panicking (mirrors safediv).
		{x: big.NewInt(17), y: big.NewInt(0), modWant: big.NewInt(0), divWant: big.NewInt(0)},
	} {
		if got := BigintBigMod(pair.x, pair.y); got.Cmp(pair.modWant) != 0 {
			t.Errorf("Mod(%s,%s) = %s, want %s", pair.x, pair.y, got, pair.modWant)
		}
		if got := BigintBigDiv(pair.x, pair.y); got.Cmp(pair.divWant) != 0 {
			t.Errorf("Div(%s,%s) = %s, want %s", pair.x, pair.y, got, pair.divWant)
		}
	}
}

// TestBigintBigFreshAllocation confirms the arithmetic helpers do not
// mutate their operands — the on-chain Script side never aliases, so the
// Go mock must not either, or tests that reuse inputs will drift from
// production semantics.
func TestBigintBigFreshAllocation(t *testing.T) {
	a := new(big.Int).Lsh(big.NewInt(1), 200)
	b := new(big.Int).Lsh(big.NewInt(3), 150)
	aSnap := new(big.Int).Set(a)
	bSnap := new(big.Int).Set(b)

	_ = BigintBigAdd(a, b)
	_ = BigintBigSub(a, b)
	_ = BigintBigMul(a, b)
	_ = BigintBigMod(a, b)
	_ = BigintBigDiv(a, b)

	if a.Cmp(aSnap) != 0 {
		t.Errorf("a was mutated by arithmetic helpers: got %s want %s", a, aSnap)
	}
	if b.Cmp(bSnap) != 0 {
		t.Errorf("b was mutated by arithmetic helpers: got %s want %s", b, bSnap)
	}
}
