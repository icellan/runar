package contract

import (
	"math/big"
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
// THIS FIXTURE USED TO RECORD A NATIVE-VS-SCRIPT DIVERGENCE. IT NO LONGER DOES.
//
// runar.EcPointX / EcPointY returned `Bigint` (int64) and reached it through
// big.Int.Int64(), so a 256-bit coordinate came back as its low 8 bytes read
// as signed -- EcPointX(3G) was -8790479930575014151 -- while codegen/ec.go's
// EmitEcPointX leaves the whole 32-byte coordinate on the stack. Every
// accessor comparison below was therefore a WIRING check: it proved the method
// called the accessor, and said nothing about the value the script compares.
//
// Both accessors and EcMakePoint take and return BigintBig now, the parameters
// here are typed to match, and `runar.BigintBigEqual(a, b)` is what the Go DSL
// parser turns into the same `===` node `a == b` produced -- the emitted script
// is byte-identical. The comparisons below are real value comparisons at 256
// bits, and the mock/emitter agreement they rest on is proved against the
// executed opcodes by the ecPointX / ecPointY / ecMakePoint rows of
// packages/runar-go/mock_script_agreement_test.go, not here.
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

// MakePoint round-trips at both widths. The small pair is the case the int64
// constructor could express; the real point is the case it could not, and is
// the one that matters -- no curve point has an 8-byte coordinate, so a
// constructor tested only at 11 and 22 was never tested on a point at all.
func TestECPrimitives_MakePointRoundTrips(t *testing.T) {
	c := ecFixture()
	mustAccept(t, "MakePoint(11, 22) round-trips", func() {
		c.CheckMakePoint(big.NewInt(11), big.NewInt(22), big.NewInt(11), big.NewInt(22))
	})
	mustRefuse(t, "MakePoint with swapped expectations", func() {
		c.CheckMakePoint(big.NewInt(11), big.NewInt(22), big.NewInt(22), big.NewInt(11))
	})

	// Past the boundary: 3G's coordinates are 256 bits, so this fails for any
	// accessor that narrows.
	p := runar.EcMulGen(3)
	x, y := runar.EcPointX(p), runar.EcPointY(p)
	if x.BitLen() <= 64 || y.BitLen() <= 64 {
		t.Fatalf("3G came back narrow (x %d bits, y %d bits) — a 256-bit "+
			"coordinate that fits in 64 bits is a truncated one", x.BitLen(), y.BitLen())
	}
	rt := runar.EcMakePoint(x, y)
	if rt != p {
		t.Fatalf("EcMakePoint(EcPointX(3G), EcPointY(3G)) = %x, want %x", rt, p)
	}
	if !runar.EcOnCurve(rt) {
		t.Fatal("the round-tripped point is not on the curve")
	}
	mustAccept(t, "CheckMakePoint on a real point", func() { c.CheckMakePoint(x, y, x, y) })
	mustRefuse(t, "CheckMakePoint on a real point, coordinates swapped", func() {
		c.CheckMakePoint(x, y, y, x)
	})
}

// The accessor-based contract methods compare 256-bit coordinates by value.
// Each mustRefuse row is the non-vacuity control for the mustAccept above it:
// without them a method that ignored its argument would pass every one.
func TestECPrimitives_AccessorMethodsCompareWholeCoordinates(t *testing.T) {
	c := ecFixture()
	x, y := runar.EcPointX(c.Pt), runar.EcPointY(c.Pt)
	// Cmp, not ==: on *big.Int, `==` is pointer identity and would be false
	// for two distinct pointers holding the same number, so the check would
	// never fire.
	if x.Cmp(y) == 0 {
		t.Fatal("EcPointX and EcPointY returned the same coordinate")
	}
	if x.BitLen() <= 64 || y.BitLen() <= 64 {
		t.Fatalf("3G came back narrow (x %d bits, y %d bits)", x.BitLen(), y.BitLen())
	}
	mustAccept(t, "CheckX on the mock's X", func() { c.CheckX(x) })
	mustRefuse(t, "CheckX off by one", func() { c.CheckX(new(big.Int).Add(x, big.NewInt(1))) })
	mustRefuse(t, "CheckX given Y", func() { c.CheckX(y) })
	mustAccept(t, "CheckY on the mock's Y", func() { c.CheckY(y) })
	mustRefuse(t, "CheckY off by one", func() { c.CheckY(new(big.Int).Add(y, big.NewInt(1))) })

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
