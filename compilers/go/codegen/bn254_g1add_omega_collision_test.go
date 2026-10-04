package codegen

import (
	"math/big"
	"testing"
)

// F-091 / CL-BUG-144: bn254G1Add on an omega-partner pair.
//
// BN254 has j-invariant 0 and p = 1 mod 3, so F_p holds a primitive cube root
// of unity w and, for any curve point P = (x, y), both (w*x, -y) and
// (w^2*x, -y) are ordinary curve points with px != qx and py + qy == 0. The
// unified slope s = (px^2 + px*qx + qx^2) / (py + qy) is then 0/0; Fermat gives
// inv(0) = 0, so s = 0 and the script used to return (-(px+qx), -py) -- a
// point that IS on the curve (so assert(bn254G1OnCurve(r)) cannot catch it)
// and is NOT P + Q.
//
// The expected values below are NOT derived from the codegen under test: they
// were computed by an independent chord/tangent reference (Python ints,
// pow(d, -1, p) for the inverse) and are pinned as literals.
//
// What this proves: the bn254G1Add builtin ABORTS on the omega collision
// (both partners, for two different P) instead of returning a value, and every
// legitimate case -- general addition, doubling, P + (-P) -> all-zero O, and
// all-zero operands -- still runs to completion with its previous answer.
// What it does not prove: anything about the Groth16 MSM accumulator, which
// shares bn254G1AffineAdd and is deliberately left unchanged.

func bn254Hex(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex %q", s)
	}
	return v
}

const (
	bn254OmegaHex = "30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48"
	// Independent reference: G + (w, p-2), true sum.
	f091RefXHex = "10216f7ba065e00c629aeebd723cc03242661d1935c4b381eeb1fa314029a9cb"
	f091RefYHex = "2042def740cbc01f6707272ba5ef5cec3b207d959e638bfafab735255afdfe20"
	// What the unpatched script returned: (w^2, p-2), on-curve and wrong.
	f091BugXHex = "000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe"
)

// runG1Add executes push(a) push(b) bn254G1Add <tail> and reports the error.
func runG1Add(t *testing.T, ax, ay, bx, by *big.Int, tail ...StackOp) error {
	t.Helper()
	var ops []StackOp
	ops = append(ops, pushPoint(ax, ay))
	ops = append(ops, pushPoint(bx, by))
	ops = append(ops, gatherOps(EmitBN254G1Add)...)
	ops = append(ops, tail...)
	return buildAndExecute(t, ops)
}

func TestBN254G1Add_OmegaCollisionAborts(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)
	w := bn254Hex(t, bn254OmegaHex)
	w2 := new(big.Int).Mod(new(big.Int).Mul(w, w), p)
	neg := func(y *big.Int) *big.Int { return new(big.Int).Sub(p, y) }
	mulw := func(c, x *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(c, x), p) }

	gx, gy := big.NewInt(1), big.NewInt(2)
	x2, y2 := bn254ComputeDoubleG(t)
	refX, refY := bn254Hex(t, f091RefXHex), bn254Hex(t, f091RefYHex)
	bugX := bn254Hex(t, f091BugXHex)

	if new(big.Int).Exp(w, big.NewInt(3), p).Cmp(big.NewInt(1)) != 0 || w.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("w is not a primitive cube root of unity mod p")
	}

	// Before the fix the script ACCEPTED the wrong point for G + (w, -2) and
	// rejected the true sum. Neither may be produced now: the builtin aborts.
	if err := runG1Add(t, gx, gy, w, neg(gy), pushPoint(bugX, neg(gy)), opcode("OP_EQUAL")); err == nil {
		t.Fatal("bn254G1Add(G, (w, -2)) returned the wrong on-curve point (w^2, -2) instead of failing closed")
	}
	if err := runG1Add(t, gx, gy, w, neg(gy), pushPoint(refX, refY), opcode("OP_EQUAL")); err == nil {
		t.Fatal("bn254G1Add(G, (w, -2)) must abort, not return a value")
	}

	collisions := []struct {
		name           string
		ax, ay, bx, by *big.Int
	}{
		{"G+(wG.x,-G.y)", gx, gy, mulw(w, gx), neg(gy)},
		{"G+(w^2G.x,-G.y)", gx, gy, mulw(w2, gx), neg(gy)},
		{"(wG.x,-G.y)+G", mulw(w, gx), neg(gy), gx, gy},
		{"2G+(w*2G.x,-2G.y)", x2, y2, mulw(w, x2), neg(y2)},
	}
	for _, tc := range collisions {
		tc := tc
		t.Run("abort/"+tc.name, func(t *testing.T) {
			// DROP the result and push 1: the script can only fail if the
			// builtin itself aborted.
			if err := runG1Add(t, tc.ax, tc.ay, tc.bx, tc.by, opcode("OP_DROP"), opcode("OP_1")); err == nil {
				t.Fatalf("%s: bn254G1Add returned a value on a 0/0 slope instead of aborting", tc.name)
			}
		})
	}

	x3, y3 := bn254ComputeAddG_2G(t)
	zx, zy := bn254AllZeroPoint()
	legit := []struct {
		name                   string
		ax, ay, bx, by, xR, yR *big.Int
	}{
		{"G+2G=3G", gx, gy, x2, y2, x3, y3},
		{"G+G=2G", gx, gy, gx, gy, x2, y2},
		{"G+(-G)=O", gx, gy, gx, neg(gy), zx, zy},
		{"2G+(-2G)=O", x2, y2, x2, neg(y2), zx, zy},
	}
	for _, tc := range legit {
		tc := tc
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := runG1Add(t, tc.ax, tc.ay, tc.bx, tc.by,
				pushPoint(tc.xR, tc.yR), opcode("OP_EQUALVERIFY"), opcode("OP_1")); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
		})
	}
	// All-zero operands: py + qy != 0 or px == qx, so the gate must not fire.
	for _, tc := range []struct {
		name           string
		ax, ay, bx, by *big.Int
	}{
		{"O+G", zx, zy, gx, gy},
		{"G+O", gx, gy, zx, zy},
		{"O+O", zx, zy, zx, zy},
	} {
		tc := tc
		t.Run("runs/"+tc.name, func(t *testing.T) {
			if err := runG1Add(t, tc.ax, tc.ay, tc.bx, tc.by, opcode("OP_DROP"), opcode("OP_1")); err != nil {
				t.Fatalf("%s: the omega gate must not fire: %v", tc.name, err)
			}
		})
	}
}
