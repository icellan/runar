package runar

import (
	"math/big"
	"testing"
)

// N-183: EcMakePoint must apply the compiled script's R-156 gate: each
// coordinate must satisfy 0 <= v < p, or the script aborts. Before the fix Go
// refused only a negative or wider-than-256-bit coordinate, so x = p, x = p+1
// and y = p (all < 2^256) built a Point.
//
// Proves: boundary operands (p, p+1, 2^256-1 on either half, plus -1 and 2^256)
// panic, and p-1 / 0 / a real curve point still build.
// Does not prove: the script itself (the runar-testing r156 test pins it).

func TestN183_EcMakePointRefusesNonFieldElements(t *testing.T) {
	gy := hexInt(t, "4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee")
	one := big.NewInt(1)
	two256 := new(big.Int).Lsh(one, 256)
	cases := []struct {
		why  string
		x, y *big.Int
	}{
		{"x = p", ecP, gy},
		{"x = p + 1", new(big.Int).Add(ecP, one), gy},
		{"y = p", one, ecP},
		{"y = p + 1", one, new(big.Int).Add(ecP, one)},
		{"x = 2^256 - 1", new(big.Int).Sub(two256, one), gy},
		{"y = 2^256 - 1", one, new(big.Int).Sub(two256, one)},
		{"x = -1", big.NewInt(-1), gy},
		{"y = -1", one, big.NewInt(-1)},
		{"x = 2^256", two256, gy},
		{"y = 2^256 + 1", one, new(big.Int).Add(two256, one)},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("EcMakePoint(%s): %s built a Point; the script aborts", c.why, c.why)
				}
			}()
			EcMakePoint(c.x, c.y)
		}()
	}
}

func TestN183_EcMakePointStillBuildsFieldElements(t *testing.T) {
	pm1 := new(big.Int).Sub(ecP, big.NewInt(1))
	gy := hexInt(t, "4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee")
	EcMakePoint(pm1, pm1)
	EcMakePoint(new(big.Int), new(big.Int))
	p := EcMakePoint(big.NewInt(1), gy)
	if EcPointY(p).Cmp(gy) != 0 {
		t.Fatalf("round trip lost y")
	}
}
