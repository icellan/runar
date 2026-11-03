package runar

import (
	"math/big"
	"testing"
)

// N-082 / F-091: the off-chain Bn254G1Add mock must fail closed on the same
// omega-partner inputs where the compiled bn254G1Add script aborts
// (compilers/go/codegen/bn254_g1add_omega_collision_test.go).
//
// The script aborts when px != qx AND (py + qy) mod p == 0. For
// Q = (w*px, -py) with w a primitive cube root of unity mod p that is the
// 0/0 slope; the mock used to return the true sum, so a native test could pass
// a contract the chain rejects.
//
// What this proves: both omega partners (w and w^2), in both operand orders,
// for G and 2G, panic in Bn254G1Add and Bn254G1AddP, and the legitimate adds
// (general, doubling, P+(-P) -> all-zero, infinity operands) keep their
// previous results, which are pinned against independent literals.
// What it does not prove: that the mock and script agree on every input (only
// this boundary), nor anything about Bn254G1ScalarMul, which is a different
// script primitive and is deliberately unguarded.

const n082OmegaHex = "30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48"

func n082Pt(x, y *big.Int) []byte { return bn254EncodePoint(x, y) }

func n082Panics(f func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	f()
	return
}

func TestBn254G1Add_OmegaPartnerFailsClosed(t *testing.T) {
	w, _ := new(big.Int).SetString(n082OmegaHex, 16)
	w2 := new(big.Int).Mod(new(big.Int).Mul(w, w), bn254P)
	if new(big.Int).Exp(w, big.NewInt(3), bn254P).Cmp(big.NewInt(1)) != 0 || w.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("w is not a primitive cube root of unity mod p")
	}
	neg := func(y *big.Int) *big.Int { return new(big.Int).Sub(bn254P, y) }
	mul := func(c, x *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(c, x), bn254P) }

	g := n082Pt(big.NewInt(1), big.NewInt(2))
	g2 := Bn254G1Add(g, g)
	g2x, g2y := bn254DecodePoint(g2)

	cases := []struct {
		name string
		a, b []byte
	}{
		{"G+(w*Gx,-Gy)", g, n082Pt(w, neg(big.NewInt(2)))},
		{"G+(w2*Gx,-Gy)", g, n082Pt(w2, neg(big.NewInt(2)))},
		{"(w*Gx,-Gy)+G", n082Pt(w, neg(big.NewInt(2))), g},
		{"2G+(w*2Gx,-2Gy)", g2, n082Pt(mul(w, g2x), neg(g2y))},
	}
	for _, tc := range cases {
		tc := tc
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			if !n082Panics(func() { Bn254G1Add(tc.a, tc.b) }) {
				t.Errorf("Bn254G1Add returned a value where the script aborts")
			}
			if !n082Panics(func() { Bn254G1AddP(Point(tc.a), Point(tc.b)) }) {
				t.Errorf("Bn254G1AddP returned a value where the script aborts")
			}
		})
	}

	// Legitimate adds are unchanged (literals from the script-side F-091 test
	// are not reproduced here; these are self-evident identities).
	zero := make([]byte, 64)
	g3 := Bn254G1Add(g, g2)
	legit := []struct {
		name       string
		a, b, want []byte
	}{
		{"G+G=2G", g, g, g2},
		{"G+(-G)=O", g, Bn254G1Negate(g), zero},
		{"2G+(-2G)=O", g2, Bn254G1Negate(g2), zero},
		{"O+G=G", zero, g, g},
		{"G+O=G", g, zero, g},
		{"O+O=O", zero, zero, zero},
		{"G+2G=3G", g, g2, g3},
		{"2G+G=3G", g2, g, g3},
	}
	for _, tc := range legit {
		tc := tc
		t.Run("accept/"+tc.name, func(t *testing.T) {
			var got []byte
			if n082Panics(func() { got = Bn254G1Add(tc.a, tc.b) }) {
				t.Fatal("legitimate add panicked")
			}
			if string(got) != string(tc.want) {
				t.Errorf("got %x want %x", got, tc.want)
			}
		})
	}
	// 3G computed independently via ScalarMul (no omega guard on that path).
	if string(Bn254G1ScalarMul(g, big.NewInt(3))) != string(g3) {
		t.Errorf("G+2G != 3G via ScalarMul")
	}
}
