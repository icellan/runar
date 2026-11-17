package codegen

// GK-BUG-007: the Groth16 MSM bind adds every term into its accumulator with
// emitG1AffineAddNamed -> bn254G1AffineAdd, the unified-slope adder
//
//	s = (px² + px·qx + qx²) / (py + qy)
//
// whose denominator vanishes for P == -Q AND for the omega partners of P,
// (w·px, -py) and (w²·px, -py), w a primitive cube root of unity mod p. Fermat
// then inverts 0 to 0, so the adder returns a point that is not P + Q:
//
//   - omega partner: (-(px+qx), -py), which IS on the curve, so a prover can
//     supply it as prepared_inputs and pass the on-curve check;
//   - P == -Q:       (-(px+qx), -py) again, off the curve, while the true sum
//     is the point at infinity.
//
// The builtin bn254G1Add aborts on both (F-091, bn254G1OmegaCollisionVerify);
// the MSM bind did not. These tests drive the MSM bind alone (q at the bottom
// of the stack, the five pub scalars, the claimed prepared_inputs) through
// the go-sdk interpreter. Expected values are independent of the codegen
// under test: the true sum comes from gnark-crypto, the bug point from the
// closed form above.
//
// Proves: the MSM bind refuses (aborts) an accumulator step whose operands
// satisfy py + qy == 0 mod p, both for the bug point and for the true sum, and
// still accepts ordinary additions and the doubling case.
// Does not prove: anything about the pairing check (the MSM bind runs here
// without the rest of the verifier).

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// gk007RunMSMBind executes emitWAGroth16MSMBind on the given config, witness
// scalars and claimed prepared_inputs, and returns the interpreter verdict.
func gk007RunMSMBind(t *testing.T, config Groth16Config, pub [5]*big.Int, piX, piY *big.Int) error {
	t.Helper()
	var ops []StackOp
	ops = append(ops, pushBigInt(bn254FieldP))
	for _, v := range pub {
		ops = append(ops, pushBigInt(v))
	}
	ops = append(ops, pushBigInt(piX), pushBigInt(piY))

	initNames := []string{
		"_qbot_p",
		"_pub_0", "_pub_1", "_pub_2", "_pub_3", "_pub_4",
		"_pi_x", "_pi_y",
	}
	emit := func(op StackOp) { ops = append(ops, op) }
	tracker := NewBN254Tracker(initNames, emit)
	tracker.qAtBottom = true
	tracker.primeCacheActive = true

	emitWAGroth16MSMBind(tracker, config)

	for len(tracker.nm) > 0 {
		tracker.drop()
	}
	ops = append(ops, opcode("OP_1"))
	return buildAndExecute(t, ops)
}

// gk007G1Add returns a + b computed by gnark-crypto (affine, canonical).
func gk007G1Add(t *testing.T, a, b [2]*big.Int) (*big.Int, *big.Int) {
	t.Helper()
	var pa, pb bn254.G1Affine
	pa.X.SetBigInt(a[0])
	pa.Y.SetBigInt(a[1])
	pb.X.SetBigInt(b[0])
	pb.Y.SetBigInt(b[1])
	if !pa.IsOnCurve() || !pb.IsOnCurve() {
		t.Fatal("gk007G1Add: operand is not on the curve")
	}
	var sum bn254.G1Affine
	sum.Add(&pa, &pb)
	if sum.IsInfinity() {
		t.Fatal("gk007G1Add: sum is the point at infinity")
	}
	var x, y big.Int
	sum.X.BigInt(&x)
	sum.Y.BigInt(&y)
	return &x, &y
}

func TestGKBUG007_MSMBindRefusesZeroDenominatorAdd(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)
	mod := func(v *big.Int) *big.Int { return new(big.Int).Mod(v, p) }
	neg := func(v *big.Int) *big.Int { return mod(new(big.Int).Neg(v)) }

	// w: primitive cube root of unity mod p (same constant F-091 pins).
	w, ok := new(big.Int).SetString(bn254OmegaHex, 16)
	if !ok {
		t.Fatal("bad omega constant")
	}
	if new(big.Int).Exp(w, big.NewInt(3), p).Cmp(big.NewInt(1)) != 0 || w.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("w is not a primitive cube root of unity mod p")
	}
	w2 := mod(new(big.Int).Mul(w, w))

	g := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	zero := big.NewInt(0)
	pubOne := [5]*big.Int{big.NewInt(1), zero, zero, zero, zero}

	// cfg builds IC = [G, ic1, G, G, G, G]; only IC[1] is ever multiplied
	// (pub = [1, 0, 0, 0, 0]), so the MSM is a single step acc = G + ic1.
	cfg := func(ic1 [2]*big.Int) Groth16Config {
		return Groth16Config{IC: [6][2]*big.Int{g, ic1, g, g, g, g}}
	}

	// bugPoint is what the unguarded unified adder returns when
	// py + qy == 0: s = 0, so (rx, ry) = (-(px+qx), -py).
	bugPoint := func(q [2]*big.Int) (*big.Int, *big.Int) {
		return neg(new(big.Int).Add(g[0], q[0])), neg(g[1])
	}

	partner1 := [2]*big.Int{mod(new(big.Int).Mul(w, g[0])), neg(g[1])}  // (w,  p-2)
	partner2 := [2]*big.Int{mod(new(big.Int).Mul(w2, g[0])), neg(g[1])} // (w², p-2)
	minusG := [2]*big.Int{new(big.Int).Set(g[0]), neg(g[1])}            // (1,  p-2)

	for _, tc := range []struct {
		name string
		ic1  [2]*big.Int
	}{
		{"G+(w*G.x,-G.y)", partner1},
		{"G+(w^2*G.x,-G.y)", partner2},
	} {
		tc := tc
		t.Run("omega_partner/"+tc.name, func(t *testing.T) {
			bx, by := bugPoint(tc.ic1)
			// The bug point is ON the curve: the on-curve check of _pi in the
			// full verifier cannot catch it.
			var bp bn254.G1Affine
			bp.X.SetBigInt(bx)
			bp.Y.SetBigInt(by)
			if !bp.IsOnCurve() {
				t.Fatal("premise broken: the omega-partner bug point is off the curve")
			}
			if err := gk007RunMSMBind(t, cfg(tc.ic1), pubOne, bx, by); err == nil {
				t.Fatalf("GK-BUG-007: MSM bind ACCEPTED the wrong on-curve accumulator (%s, %s) for %s", bx, by, tc.name)
			}
			tx, ty := gk007G1Add(t, g, tc.ic1)
			if err := gk007RunMSMBind(t, cfg(tc.ic1), pubOne, tx, ty); err == nil {
				t.Fatalf("MSM bind must abort on a zero-denominator step, but accepted the true sum for %s", tc.name)
			}
		})
	}

	t.Run("P_plus_minus_P", func(t *testing.T) {
		// True sum is the point at infinity (no affine prepared_inputs); the
		// unguarded adder yields (-2, -2) mod p.
		bx, by := bugPoint(minusG)
		if err := gk007RunMSMBind(t, cfg(minusG), pubOne, bx, by); err == nil {
			t.Fatalf("GK-BUG-007: MSM bind ACCEPTED (%s, %s) as G + (-G)", bx, by)
		}
	})

	// Controls: the guard must not refuse a legitimate step.
	t.Run("control/general_add_G+2G", func(t *testing.T) {
		twoG := [2]*big.Int{}
		twoG[0], twoG[1] = bn254ComputeDoubleG(t)
		ex, ey := gk007G1Add(t, g, twoG)
		if err := gk007RunMSMBind(t, cfg(twoG), pubOne, ex, ey); err != nil {
			t.Fatalf("MSM bind rejected the honest accumulator G + 2G: %v", err)
		}
	})
	t.Run("control/doubling_G+G", func(t *testing.T) {
		ex, ey := bn254ComputeDoubleG(t)
		if err := gk007RunMSMBind(t, cfg(g), pubOne, ex, ey); err != nil {
			t.Fatalf("MSM bind rejected the honest accumulator G + G = 2G: %v", err)
		}
	})
}
