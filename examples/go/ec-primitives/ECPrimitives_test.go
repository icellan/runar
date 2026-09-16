package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestECPrimitives_Compile(t *testing.T) {
	if err := runar.CompileCheck("ECPrimitives.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// 3*G, derived rather than hard-coded so these rows cannot drift away from the
// SDK's own arithmetic.
func ecFixture() *ECPrimitives {
	return &ECPrimitives{Pt: runar.EcMulGen(3)}
}

// ---------------------------------------------------------------------------
// A RECORDED NATIVE-VS-SCRIPT DIVERGENCE LIVES IN THIS FIXTURE.
//
// runar.EcPointX / EcPointY return `Bigint`, which the Go mock aliases to
// int64, and they reach it through big.Int.Int64(). A secp256k1 coordinate is
// 256 bits, so the mock returns the low 8 bytes REINTERPRETED AS SIGNED --
// EcPointX(3G) is -8790479930575014151 -- while codegen/ec.go's EmitEcPointX
// leaves the whole 32-byte coordinate on the stack. The divergence is pinned
// as `knownDivergent` in packages/runar-go/mock_script_agreement_test.go and
// is the same root cause that keeps examples/go/schnorr-zkp,
// examples/go/p256-primitives and examples/go/p384-primitives out of the Go
// build entirely: Rúnar's `bigint` is arbitrary precision and Go's is not.
//
// So the tests below are deliberately split. Everything that compares whole
// POINTS is faithful and is checked against independently derived points.
// Everything that goes through a coordinate accessor is a WIRING check only --
// it proves the contract calls the accessor and compares the result, and it
// says nothing about the 256-bit value the script would compare. Treating
// those rows as cryptographic agreement is the mistake this comment exists to
// prevent.
// ---------------------------------------------------------------------------

func TestECPrimitives_OnCurveAndNegate(t *testing.T) {
	c := ecFixture()
	mustAccept(t, "CheckOnCurve", func() { c.CheckOnCurve() })

	// Whole-point comparisons: faithful, no accessor involved.
	neg := runar.EcNegate(c.Pt)
	if neg == c.Pt {
		t.Fatal("EcNegate returned its input")
	}
	if !runar.EcOnCurve(neg) {
		t.Fatal("EcNegate produced a point off the curve")
	}
	if runar.EcNegate(neg) != c.Pt {
		t.Fatal("EcNegate is not an involution")
	}
	mustAccept(t, "CheckNegateRoundtrip", func() { c.CheckNegateRoundtrip() })
}

// Group law, checked against an independently derived point: 3G + 4G == 7G,
// compared as whole points rather than through the accessors.
func TestECPrimitives_AddAgreesWithScalarMultiplication(t *testing.T) {
	c := ecFixture()
	other := runar.EcMulGen(4)

	if got, want := runar.EcAdd(c.Pt, other), runar.EcMulGen(7); got != want {
		t.Fatalf("3G + 4G != 7G")
	}
	if got, want := runar.EcMul(c.Pt, 5), runar.EcMulGen(15); got != want {
		t.Fatalf("5 * 3G != 15G")
	}
	if got := runar.EcMul(c.Pt, 1); got != c.Pt {
		t.Fatal("1 * P != P")
	}
	mustAccept(t, "CheckAddOnCurve", func() { c.CheckAddOnCurve(other) })
	mustAccept(t, "CheckMulGenOnCurve", func() { c.CheckMulGenOnCurve(11) })
	mustAccept(t, "CheckMulIdentity", func() { c.CheckMulIdentity() })
}

func TestECPrimitives_EncodeCompressed(t *testing.T) {
	c := ecFixture()
	enc := runar.EcEncodeCompressed(c.Pt)
	if len(enc) != 33 {
		t.Fatalf("compressed encoding is %d bytes, want 33", len(enc))
	}
	if enc[0] != 0x02 && enc[0] != 0x03 {
		t.Fatalf("compressed prefix is 0x%02x, want 0x02 or 0x03", enc[0])
	}
	// The parity prefix must actually track Y: P and -P share an X and differ
	// only in the prefix byte.
	negEnc := runar.EcEncodeCompressed(runar.EcNegate(c.Pt))
	if negEnc[0] == enc[0] {
		t.Fatal("EcEncodeCompressed gave P and -P the same parity prefix")
	}
	if negEnc[1:] != enc[1:] {
		t.Fatal("EcEncodeCompressed gave P and -P different X bytes")
	}

	mustAccept(t, "CheckEncodeCompressed", func() { c.CheckEncodeCompressed(enc) })
	mustRefuse(t, "CheckEncodeCompressed against -P", func() { c.CheckEncodeCompressed(negEnc) })
	mustRefuse(t, "CheckEncodeCompressed against another point", func() {
		c.CheckEncodeCompressed(runar.EcEncodeCompressed(runar.EcMulGen(4)))
	})
}

// EcModReduce takes and returns plain integers, so it is exact in the mock.
func TestECPrimitives_ModReduce(t *testing.T) {
	c := ecFixture()
	for _, r := range []struct{ v, m, want runar.Bigint }{
		{17, 5, 2},
		{-3, 5, 2}, // the reduction is non-negative: ((v % m) + m) % m
		{0, 5, 0},
		{5, 5, 0},
	} {
		v, m, want := r.v, r.m, r.want
		if got := runar.EcModReduce(v, m); got != want {
			t.Fatalf("EcModReduce(%d, %d) = %d, want %d", v, m, got, want)
		}
		mustAccept(t, "CheckModReduce", func() { c.CheckModReduce(v, m, want) })
		mustRefuse(t, "CheckModReduce off by one", func() { c.CheckModReduce(v, m, want+1) })
	}
}

// MakePoint round-trips only for coordinates that FIT in int64. Small values
// are used on purpose: with a real curve point the accessors truncate and the
// round trip produces a point that is not even on the curve. That is the
// recorded divergence above, demonstrated rather than asserted away.
func TestECPrimitives_MakePointRoundTripsSmallCoordinates(t *testing.T) {
	c := ecFixture()
	mustAccept(t, "MakePoint(11, 22) round-trips", func() {
		c.CheckMakePoint(11, 22, 11, 22)
	})
	mustRefuse(t, "MakePoint with swapped expectations", func() {
		c.CheckMakePoint(11, 22, 22, 11)
	})

	// The demonstration. A real coordinate does not survive the accessor, so
	// the round trip leaves the curve. If this ever starts round-tripping,
	// EcPointX has been widened and the `knownDivergent` entry in
	// packages/runar-go/mock_script_agreement_test.go is stale.
	p := runar.EcMulGen(3)
	rt := runar.EcMakePoint(runar.EcPointX(p), runar.EcPointY(p))
	if rt == p {
		t.Fatal("EcPointX/EcPointY now round-trip a 256-bit coordinate: the " +
			"int64 truncation is fixed and the knownDivergent entry in " +
			"packages/runar-go/mock_script_agreement_test.go must be removed")
	}
	if runar.EcOnCurve(rt) {
		t.Fatal("the truncated round trip landed back on the curve, which the " +
			"low 64 bits of a secp256k1 X should not do")
	}
}

// The accessor-based contract methods are WIRING checks only -- see the
// divergence note above. They prove the method calls the accessor and compares
// its result; they do not prove agreement with the 256-bit value the script
// compares.
func TestECPrimitives_AccessorMethodsAreWired(t *testing.T) {
	c := ecFixture()
	x, y := runar.EcPointX(c.Pt), runar.EcPointY(c.Pt)
	if x == y {
		t.Fatal("EcPointX and EcPointY returned the same coordinate")
	}
	mustAccept(t, "CheckX on the mock's X", func() { c.CheckX(x) })
	mustRefuse(t, "CheckX off by one", func() { c.CheckX(x + 1) })
	mustRefuse(t, "CheckX given Y", func() { c.CheckX(y) })
	mustAccept(t, "CheckY on the mock's Y", func() { c.CheckY(y) })
	mustRefuse(t, "CheckY off by one", func() { c.CheckY(y + 1) })

	negY := runar.EcPointY(runar.EcNegate(c.Pt))
	mustAccept(t, "CheckNegateY", func() { c.CheckNegateY(negY) })
	mustRefuse(t, "CheckNegateY given the un-negated Y", func() { c.CheckNegateY(y) })

	seven := runar.EcMulGen(7)
	mustAccept(t, "CheckAdd", func() {
		c.CheckAdd(runar.EcMulGen(4), runar.EcPointX(seven), runar.EcPointY(seven))
	})
	mustRefuse(t, "CheckAdd against 8G", func() {
		eight := runar.EcMulGen(8)
		c.CheckAdd(runar.EcMulGen(4), runar.EcPointX(eight), runar.EcPointY(eight))
	})

	nine := runar.EcMulGen(9)
	mustAccept(t, "CheckMul(3) reaches 9G", func() {
		c.CheckMul(3, runar.EcPointX(nine), runar.EcPointY(nine))
	})
	g := runar.EcMulGen(1)
	mustAccept(t, "CheckMulGen(1) == G", func() {
		c.CheckMulGen(1, runar.EcPointX(g), runar.EcPointY(g))
	})
	mustRefuse(t, "CheckMulGen(1) against 2G", func() {
		two := runar.EcMulGen(2)
		c.CheckMulGen(1, runar.EcPointX(two), runar.EcPointY(two))
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
