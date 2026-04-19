package codegen

import (
	"math/big"
	"testing"
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
