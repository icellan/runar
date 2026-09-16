package contract

import (
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// P384Point is x[48] || y[48], big-endian, no prefix byte.
const P384EncodeNegateCoordLen = 48

func TestP384EncodeNegate_Compile(t *testing.T) {
	if err := runar.CompileCheck("P384EncodeNegate.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestP384EncodeNegate_NegateAndEncode(t *testing.T) {
	// Derived, not hard-coded, so the test cannot drift away from the SDK's
	// own encoding.
	p := runar.P384MulGen(big.NewInt(7))
	if !runar.P384OnCurve(p) {
		t.Fatal("P384MulGen(7) is not on the curve")
	}
	n := runar.P384Negate(p)

	px, py := string(p)[:P384EncodeNegateCoordLen], string(p)[P384EncodeNegateCoordLen:]
	nx, ny := string(n)[:P384EncodeNegateCoordLen], string(n)[P384EncodeNegateCoordLen:]

	// Negation flips Y and fixes X. A "negate" that returned its input, or
	// that negated X instead, passes a test that only checks OnCurve.
	if n == p {
		t.Fatal("P384Negate returned its input")
	}
	if nx != px {
		t.Fatal("P384Negate changed X")
	}
	if ny == py {
		t.Fatal("P384Negate left Y unchanged")
	}
	if !runar.P384OnCurve(n) {
		t.Fatal("P384Negate produced a point off the curve")
	}
	if runar.P384Negate(n) != p {
		t.Fatal("P384Negate is not an involution")
	}

	mustAccept(t, "CheckNegate on the real negation", func() {
		(&P384EncodeNegate{}).CheckNegate(p, n)
	})
	mustRefuse(t, "CheckNegate against the un-negated point", func() {
		(&P384EncodeNegate{}).CheckNegate(p, p)
	})

	enc := runar.P384EncodeCompressed(n)
	if len(enc) != P384EncodeNegateCoordLen+1 {
		t.Fatalf("compressed encoding is %d bytes, want %d", len(enc), P384EncodeNegateCoordLen+1)
	}
	mustAccept(t, "CheckEncode on the real encoding", func() {
		(&P384EncodeNegate{}).CheckEncode(n, enc)
	})
	mustRefuse(t, "CheckEncode against the other point's encoding", func() {
		(&P384EncodeNegate{}).CheckEncode(n, runar.P384EncodeCompressed(p))
	})

	// The compound method must agree with the two steps run separately.
	mustAccept(t, "CheckNegateThenEncode", func() {
		(&P384EncodeNegate{ExpectedCompressed: enc}).CheckNegateThenEncode(p)
	})
	mustRefuse(t, "CheckNegateThenEncode skipped the negation", func() {
		(&P384EncodeNegate{ExpectedCompressed: runar.P384EncodeCompressed(p)}).CheckNegateThenEncode(p)
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
