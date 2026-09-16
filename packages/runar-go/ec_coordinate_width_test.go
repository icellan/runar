package runar

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// THE SECP256K1 COORDINATE DOMAIN IS 256 BITS WIDE.
//
// EcPointX / EcPointY / EcMakePoint move curve coordinates between a Point and
// the Rúnar `bigint` domain. Every one of those coordinates is 256 bits. While
// the three were typed `Bigint` (= int64) the accessors reached the answer via
// big.Int.Int64(), which keeps the low 8 bytes and reinterprets them as
// signed — EcPointX(3G) came back as -8790479930575014151 — and EcMakePoint
// could only build a point out of coordinates that fit in 8 bytes, which no
// real curve point does.
//
// The expected coordinates below are the published secp256k1 values for 2G and
// 3G. They are written out as hex constants on purpose: deriving them from
// EcMulGen would make this file agree with the code it is testing no matter
// what that code does.
//
// The Script-side half of this proof is not here. It is the ecPointX /
// ecPointY / ecMakePoint rows of mock_script_agreement_test.go, which push a
// real point at the compiled opcodes on the go-sdk consensus interpreter and
// require the mock's answer to be the one the script accepts.
// ---------------------------------------------------------------------------

func hexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex constant %q", s)
	}
	return v
}

// Published secp256k1 multiples of the generator.
const (
	g2XHex = "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
	g2YHex = "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"
	g3XHex = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
	g3YHex = "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"
)

func TestEcPointXY_CarryTheWholeCoordinate(t *testing.T) {
	rows := []struct {
		name  string
		k     int64
		wantX string
		wantY string
	}{
		{name: "2G", k: 2, wantX: g2XHex, wantY: g2YHex},
		{name: "3G", k: 3, wantX: g3XHex, wantY: g3YHex},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := EcMulGen(r.k)
			wantX := hexInt(t, r.wantX)
			wantY := hexInt(t, r.wantY)

			gotX := EcPointX(p)
			if gotX.Cmp(wantX) != 0 {
				t.Errorf("EcPointX(%s) = %s, want %s", r.name, gotX, wantX)
			}
			gotY := EcPointY(p)
			if gotY.Cmp(wantY) != 0 {
				t.Errorf("EcPointY(%s) = %s, want %s", r.name, gotY, wantY)
			}

			// Past the boundary, explicitly: a value that agreed with a
			// truncating accessor would have to fit in 64 bits.
			if gotX.BitLen() <= 64 || gotY.BitLen() <= 64 {
				t.Errorf("%s coordinates came back narrow (x %d bits, y %d bits) — "+
					"a 256-bit coordinate that fits in 64 bits is a truncated one",
					r.name, gotX.BitLen(), gotY.BitLen())
			}
		})
	}
}

// TestEcMakePoint_RoundTripsARealPoint is the assertion examples/go/ec-unit's
// contract makes and its test suite could not run: rebuilding a point from its
// own coordinates has to land back on the curve. With int64 coordinates the
// rebuilt point was 48 bytes of zeroes and 16 bytes of low-order noise, so the
// round-trip was never executed natively — the test file said so in a comment
// instead.
func TestEcMakePoint_RoundTripsARealPoint(t *testing.T) {
	for _, k := range []int64{1, 2, 3, 7, 1 << 40} {
		p := EcMulGen(k)
		rebuilt := EcMakePoint(EcPointX(p), EcPointY(p))
		if rebuilt != p {
			t.Fatalf("EcMakePoint(EcPointX(%[1]dG), EcPointY(%[1]dG)) = %x, want %x", k, rebuilt, p)
		}
		if !EcOnCurve(rebuilt) {
			t.Fatalf("round-tripped %dG is not on the curve", k)
		}
	}
}

// TestEcMakePoint_PadsShortCoordinates keeps the wide constructor honest about
// the narrow case: a coordinate that happens to be small still has to land in
// the low bytes of its 32-byte field, not at the front of it.
func TestEcMakePoint_PadsShortCoordinates(t *testing.T) {
	p := EcMakePoint(big.NewInt(11), big.NewInt(22))
	if len(p) != 64 {
		t.Fatalf("EcMakePoint produced %d bytes, want 64", len(p))
	}
	if p[31] != 11 || p[63] != 22 {
		t.Fatalf("EcMakePoint(11, 22) = %x, want 11 and 22 in the last byte of each half", p)
	}
	for i, b := range []byte(p) {
		if i != 31 && i != 63 && b != 0 {
			t.Fatalf("EcMakePoint(11, 22) has a nonzero byte at %d: %x", i, p)
		}
	}
}
