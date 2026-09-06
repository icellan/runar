package codegen

import (
	"math/big"
	"testing"
)

// The comb's compile-time half: the table, and the interval checker that
// decides where the cheap incomplete addition may be used.
//
// These are absolute vectors, not differential ones. The table is built from
// this tier's own arithmetic, so comparing it against this tier's own ladder
// would only prove the two agree — including on a shared error. Published
// multiples of G are the independent oracle.

var combCurves = []struct {
	name  string
	curve *CombCurve
}{
	{"P-256", P256CombCurve},
	{"P-384", P384CombCurve},
	{"secp256k1", Secp256k1CombCurve},
}

func TestCombPublishedDoublings(t *testing.T) {
	cases := []struct {
		name  string
		curve *CombCurve
		x, y  string
	}{
		{"P-256", P256CombCurve,
			"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
			"07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"},
		// secp256k1 has a = 0, so the tangent numerator is 3x² with no `+ a`
		// term. A curve record that copied the NIST a = -3 would still produce
		// points that pass the on-curve check for the WRONG curve.
		{"secp256k1", Secp256k1CombCurve,
			"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
			"1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			two := CombScalarMul(big.NewInt(2), tc.curve.G, tc.curve)
			if two == nil {
				t.Fatal("2G came back as the point at infinity")
			}
			if two.X.Cmp(hexBig(tc.x)) != 0 || two.Y.Cmp(hexBig(tc.y)) != 0 {
				t.Fatalf("2G = (%x, %x), want (%s, %s)", two.X, two.Y, tc.x, tc.y)
			}
		})
	}
}

func TestCombSecp256k1CoefficientsAreNotNIST(t *testing.T) {
	if Secp256k1CombCurve.A.Sign() != 0 {
		t.Fatalf("secp256k1 a = %v, want 0", Secp256k1CombCurve.A)
	}
	if Secp256k1CombCurve.B.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("secp256k1 b = %v, want 7", Secp256k1CombCurve.B)
	}
}

func TestCombOrderKillsG(t *testing.T) {
	for _, c := range combCurves {
		if pt := CombScalarMul(c.curve.N, c.curve.G, c.curve); pt != nil {
			t.Fatalf("%s: n·G = (%x, %x), want the point at infinity", c.name, pt.X, pt.Y)
		}
	}
}

func TestCombTablePointsAreOnTheCurve(t *testing.T) {
	for _, c := range combCurves {
		for _, w := range []int{2, 3, 4} {
			params := CombGeometry(w, c.curve)
			if params == nil {
				t.Fatalf("%s: no geometry for w=%d", c.name, w)
			}
			for j, pt := range CombTable(w, params.D, c.curve) {
				if pt == nil {
					continue
				}
				lhs := combMod(new(big.Int).Mul(pt.Y, pt.Y), c.curve.P)
				rhs := new(big.Int).Mul(new(big.Int).Mul(pt.X, pt.X), pt.X)
				rhs.Add(rhs, new(big.Int).Mul(c.curve.A, pt.X))
				rhs.Add(rhs, c.curve.B)
				if combMod(rhs, c.curve.P).Cmp(lhs) != 0 {
					t.Fatalf("%s w=%d: table entry %d is off the curve", c.name, w, j)
				}
			}
		}
	}
}

func TestCombTableEntryIsCombValueTimesG(t *testing.T) {
	w := 3
	params := CombGeometry(w, P256CombCurve)
	table := CombTable(w, params.D, P256CombCurve)
	for j := 1; j < (1 << w); j++ {
		want := CombScalarMul(CombValue(j, params.D), P256CombCurve.G, P256CombCurve)
		if table[j].X.Cmp(want.X) != 0 || table[j].Y.Cmp(want.Y) != 0 {
			t.Fatalf("entry %d != CombValue(%d)·G", j, j)
		}
	}
	if table[0] != nil {
		t.Fatal("entry 0 must be the point at infinity and never added")
	}
}

// The geometry search is the reason the comb cannot just reuse the ladder's
// hardcoded +3n: that happens to be right for P-256 and secp256k1 at w=3 and
// wrong for P-384, where a zero leading digit would start the accumulator at
// infinity.
func TestCombGeometryPicksTheOffsetPerCurve(t *testing.T) {
	p256 := CombGeometry(3, P256CombCurve)
	if p256.OffsetMultiple.Int64() != 3 || p256.D != 86 {
		t.Fatalf("P-256 w=3: got m=%v d=%d, want m=3 d=86", p256.OffsetMultiple, p256.D)
	}
	k1 := CombGeometry(3, Secp256k1CombCurve)
	if k1.OffsetMultiple.Int64() != 3 || k1.D != 86 {
		t.Fatalf("secp256k1 w=3: got m=%v d=%d, want m=3 d=86", k1.OffsetMultiple, k1.D)
	}
	p384 := CombGeometry(3, P384CombCurve)
	if p384.OffsetMultiple.Int64() == 3 {
		t.Fatal("P-384 w=3 must NOT land on the ladder's +3n")
	}
	for _, c := range combCurves {
		g := CombGeometry(3, c.curve)
		top := new(big.Int).Lsh(big.NewInt(1), uint(g.W*g.D-1))
		cap_ := new(big.Int).Lsh(big.NewInt(1), uint(g.W*g.D))
		if g.Lo.Cmp(top) < 0 || g.Hi.Cmp(cap_) >= 0 {
			t.Fatalf("%s: scalar domain escapes the digit width", c.name)
		}
	}
}

func TestCombSafeRoundsProvesMostAndRefusesTheTail(t *testing.T) {
	for _, c := range combCurves {
		params := CombGeometry(3, c.curve)
		safe := CombSafeRounds(params, c.curve)
		if len(safe) != params.D {
			t.Fatalf("%s: %d verdicts for %d rounds", c.name, len(safe), params.D)
		}
		proved := 0
		for _, s := range safe {
			if s {
				proved++
			}
		}
		if proved <= params.D-8 {
			t.Fatalf("%s: only %d/%d rounds proved", c.name, proved, params.D)
		}
		// The interval widens as i falls; once it can wrap a full residue class
		// the checker MUST give up rather than assume. A checker that proved
		// every round would be broken, not clever.
		if safe[0] {
			t.Fatalf("%s: round 0 must not be provable", c.name)
		}
		if safe[params.D-1] {
			t.Fatalf("%s: the initialising round performs no add", c.name)
		}
	}
}

// Widening the scalar domain can only make rounds LESS provable. A checker that
// gained confidence from a looser precondition would be unsound.
func TestCombSafeRoundsIsMonotone(t *testing.T) {
	params := CombGeometry(3, Secp256k1CombCurve)
	strict := CombSafeRounds(params, Secp256k1CombCurve)
	loose := CombSafeRounds(&CombParams{
		W: params.W, D: params.D, OffsetMultiple: params.OffsetMultiple,
		Lo: params.Lo, Hi: new(big.Int).Lsh(params.Hi, 1),
	}, Secp256k1CombCurve)
	for i := range strict {
		if loose[i] && !strict[i] {
			t.Fatalf("round %d became provable under a WIDER domain", i)
		}
	}
}
