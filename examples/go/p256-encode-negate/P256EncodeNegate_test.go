package contract

import (
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// P256Point is x[32] || y[32], big-endian, no prefix byte.
const P256EncodeNegateCoordLen = 32

func TestP256EncodeNegate_Compile(t *testing.T) {
	if err := runar.CompileCheck("P256EncodeNegate.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestP256EncodeNegate_NegateAndEncode(t *testing.T) {
	// Derived, not hard-coded, so the test cannot drift away from the SDK's
	// own encoding.
	p := runar.P256MulGen(big.NewInt(7))
	if !runar.P256OnCurve(p) {
		t.Fatal("P256MulGen(7) is not on the curve")
	}
	n := runar.P256Negate(p)

	px, py := string(p)[:P256EncodeNegateCoordLen], string(p)[P256EncodeNegateCoordLen:]
	nx, ny := string(n)[:P256EncodeNegateCoordLen], string(n)[P256EncodeNegateCoordLen:]

	// Negation flips Y and fixes X. A "negate" that returned its input, or
	// that negated X instead, passes a test that only checks OnCurve.
	if n == p {
		t.Fatal("P256Negate returned its input")
	}
	if nx != px {
		t.Fatal("P256Negate changed X")
	}
	if ny == py {
		t.Fatal("P256Negate left Y unchanged")
	}
	if !runar.P256OnCurve(n) {
		t.Fatal("P256Negate produced a point off the curve")
	}
	if runar.P256Negate(n) != p {
		t.Fatal("P256Negate is not an involution")
	}

	mustAccept(t, "CheckNegate on the real negation", func() {
		(&P256EncodeNegate{}).CheckNegate(p, n)
	})
	mustRefuse(t, "CheckNegate against the un-negated point", func() {
		(&P256EncodeNegate{}).CheckNegate(p, p)
	})

	enc := runar.P256EncodeCompressed(n)
	if len(enc) != P256EncodeNegateCoordLen+1 {
		t.Fatalf("compressed encoding is %d bytes, want %d", len(enc), P256EncodeNegateCoordLen+1)
	}
	mustAccept(t, "CheckEncode on the real encoding", func() {
		(&P256EncodeNegate{}).CheckEncode(n, enc)
	})
	mustRefuse(t, "CheckEncode against the other point's encoding", func() {
		(&P256EncodeNegate{}).CheckEncode(n, runar.P256EncodeCompressed(p))
	})

	// The compound method must agree with the two steps run separately.
	mustAccept(t, "CheckNegateThenEncode", func() {
		(&P256EncodeNegate{ExpectedCompressed: enc}).CheckNegateThenEncode(p)
	})
	mustRefuse(t, "CheckNegateThenEncode skipped the negation", func() {
		(&P256EncodeNegate{ExpectedCompressed: runar.P256EncodeCompressed(p)}).CheckNegateThenEncode(p)
	})
}

func mustAccept(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: the contract REFUSED (%v)", what, r)
		}
	}()
	fn()
}

func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED where it must refuse", what)
		}
	}()
	fn()
}
