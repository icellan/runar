package codegen

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// TestMSMBindZeroSkipEmitsIF verifies that emitWAGroth16MSMBind emits one
// OP_0NOTEQUAL guard per MSM term (5 total) and wraps each term in an
// OP_IF/OP_ELSE so that pub_i == 0 is handled as a no-op instead of
// feeding the identity-producing scalar-mul trajectory that used to
// break the on-chain accumulator for SP1 fixtures with pub_2 = 0 and
// pub_4 = 0.
func TestMSMBindZeroSkipEmitsIF(t *testing.T) {
	dummyPoint := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	config := Groth16Config{
		IC: [6][2]*big.Int{
			dummyPoint, dummyPoint, dummyPoint, dummyPoint, dummyPoint, dummyPoint,
		},
	}

	initNames := []string{"_pub_0", "_pub_1", "_pub_2", "_pub_3", "_pub_4", "_pi_x", "_pi_y"}

	var ops []StackOp
	emit := func(op StackOp) { ops = append(ops, op) }
	tracker := NewBN254Tracker(initNames, emit)
	tracker.qAtBottom = true
	tracker.primeCacheActive = true

	emitWAGroth16MSMBind(tracker, config)

	var notequalCount, ifCount int
	for _, op := range ops {
		if op.Op == "opcode" && op.Code == "OP_0NOTEQUAL" {
			notequalCount++
		}
		if op.Op == "if" {
			ifCount++
		}
	}
	if notequalCount != 5 {
		t.Errorf("expected 5 OP_0NOTEQUAL (one per MSM term), got %d", notequalCount)
	}
	if ifCount < 5 {
		t.Errorf("expected at least 5 top-level IF ops (one per MSM term), got %d", ifCount)
	}
}

// TestMSMBind_ScalarMulZeroIsSkipped builds a minimal MSM-bind script
// where every IC slot is the BN254 generator G and the public inputs
// mirror the SP1 v6 shape (three nonzero scalars, two exactly zero).
// Runs the compiled script through the in-process Bitcoin Script
// interpreter and asserts the MSM equality check accepts the expected
// prepared_inputs point. Regression guard for two independent codegen
// bugs:
//
//  1. `emitWAGroth16MSMBind` previously fed scalar=0 into
//     `emitG1ScalarMulNamed`, whose Jacobian double-and-add hits the
//     unhandled acc = -base case and silently produced the wrong point.
//  2. `bn254BuildJacobianAddAffineInline` forgot to propagate the outer
//     tracker's `qAtBottom` flag to its inner double/add sub-trackers,
//     so their nested field-arithmetic ops emitted OP_FROMALTSTACK into
//     a universe where the prime was at the bottom of the main stack.
func TestMSMBind_ScalarMulZeroIsSkipped(t *testing.T) {
	pub := [5]int{7, 11, 0, 13, 0}

	// All IC slots = G: reduces the MSM to
	//   msm = IC[0] + Σ pub_i · IC[i+1]
	//       = G + (pub_0 + pub_1 + pub_3) · G
	//       = (1 + pub_0 + pub_1 + pub_3) · G
	genG := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	config := Groth16Config{
		IC: [6][2]*big.Int{genG, genG, genG, genG, genG, genG},
	}

	total := 1
	for _, v := range pub {
		total += v
	}
	expX, expY := bn254ComputeKG(t, total)

	var ops []StackOp
	ops = append(ops, pushBigInt(bn254FieldP))
	for _, v := range pub {
		ops = append(ops, pushBigInt(big.NewInt(int64(v))))
	}
	ops = append(ops, pushBigInt(expX), pushBigInt(expY))

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

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("MSM bind script failed: %v", err)
	}
}

// TestMSMBind_PublicInputIsReducedModR — F-036 (CL-BUG-039 / GK-BUG-008).
//
// The pub_i scalars are witness-supplied, so their domain is whatever the
// spender pushes. The off-chain SDK (bn254witness.computePreparedInputs)
// reduces each one mod r before the scalar-mul, so it treats pub_i and
// pub_i mod r as the same statement. emitWAGroth16MSMBind must agree, or the
// on-chain binding and the SDK compute different accumulators for the same
// witness. This test drives the MSM binding with DELIBERATELY out-of-domain
// scalars and an accumulator computed the SDK's way (gnark, scalars mod r),
// and executes the emitted script on the go-sdk interpreter.
//
// Cases:
//   - pub_0 = r: the SDK sees 0, so the accumulator is IC[0]. The unreduced
//     ladder instead ran k' = 4r through the zero-flag's NONZERO branch and
//     produced the point at infinity's garbage affine image.
//   - pub_0 = 2^256 - 3r + 5: k + 3r sets bit 256, which the unreduced
//     ladder never reads, so it bound 5·IC[1] instead of (k mod r)·IC[1].
//   - pub_0 = r + 7 (control): in the ladder's accidental working range, so
//     it must keep binding as 7·IC[1].
//   - pub = -1 (control for the negative half of the reduce).
//
// Proves: for these witnesses the on-chain accumulator equals the SDK's
// scalars-mod-r accumulator. Does NOT prove: anything about the pairing or
// the rest of the verifier (see compiler/groth16_wa_binding_test.go for the
// full-artifact spend), nor that accepting a non-canonical pub_i >= r is the
// right policy for contract bodies that read groth16PublicInput(i) — those
// still see the raw witness value.
func TestMSMBind_PublicInputIsReducedModR(t *testing.T) {
	r := new(big.Int).Set(bn254CurveR)
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	bit256 := new(big.Int).Sub(two256, new(big.Int).Mul(r, big.NewInt(3)))
	bit256.Add(bit256, big.NewInt(5))

	cases := []struct {
		name string
		pub  [5]*big.Int
	}{
		{"pub0=r", [5]*big.Int{new(big.Int).Set(r), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}},
		{"pub0=2^256-3r+5", [5]*big.Int{bit256, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}},
		{"pub0=r+7_control", [5]*big.Int{new(big.Int).Add(r, big.NewInt(7)), big.NewInt(11), big.NewInt(0), big.NewInt(13), big.NewInt(0)}},
		{"pub1=-1_control", [5]*big.Int{big.NewInt(3), big.NewInt(-1), big.NewInt(0), big.NewInt(0), big.NewInt(0)}},
	}

	// All IC slots = G: msm = (1 + Σ (pub_i mod r)) · G — the SDK's view.
	genG := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	config := Groth16Config{
		IC: [6][2]*big.Int{genG, genG, genG, genG, genG, genG},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total := big.NewInt(1)
			for _, v := range tc.pub {
				total.Add(total, new(big.Int).Mod(v, r))
			}
			_, _, g1, _ := bn254.Generators()
			var exp bn254.G1Affine
			exp.ScalarMultiplication(&g1, new(big.Int).Mod(total, r))
			var expX, expY big.Int
			exp.X.BigInt(&expX)
			exp.Y.BigInt(&expY)

			var ops []StackOp
			ops = append(ops, pushBigInt(bn254FieldP))
			for _, v := range tc.pub {
				ops = append(ops, pushBigInt(v))
			}
			ops = append(ops, pushBigInt(&expX), pushBigInt(&expY))

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

			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("on-chain MSM binding disagrees with the SDK's scalars-mod-r accumulator: %v", err)
			}
		})
	}
}
