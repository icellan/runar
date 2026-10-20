package codegen

import (
	"math/big"
	"testing"
)

// TestMSMBind_PinnedSlotsFoldIntoStart mirrors TestMSMBind_ScalarMulZeroIsSkipped
// with three of the five public inputs pinned (the SP1 shape: vkey hash,
// exit code = 0, vk root). Every IC slot is the generator G, so
//
//	prepared = (1 + pub_0 + pub_1 + pub_3) · G
//
// regardless of which slots are pinned. The test checks three things:
//
//  1. pinned slots emit no scalar-multiplication branch (the OP_0NOTEQUAL
//     zero-guard count drops from 5 to the number of unpinned slots);
//  2. the script still accepts the correct prepared_inputs point, i.e. the
//     folded starting point plus the on-chain terms equals the full MSM;
//  3. a witness scalar that disagrees with its pinned value is rejected,
//     and so is the correct witness paired with a wrong prepared point.
func TestMSMBind_PinnedSlotsFoldIntoStart(t *testing.T) {
	pub := [5]int{7, 11, 0, 13, 0}
	pinned := map[int]bool{0: true, 2: true, 3: true}

	genG := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	config := Groth16Config{
		IC: [6][2]*big.Int{genG, genG, genG, genG, genG, genG},
	}
	for i := range pub {
		if pinned[i] {
			config.PinnedPublicInputs[i] = big.NewInt(int64(pub[i]))
		}
	}

	total := 1
	for _, v := range pub {
		total += v
	}
	expX, expY := bn254ComputeKG(t, total)

	build := func(scalars [5]int, piX, piY *big.Int) ([]StackOp, []StackOp) {
		var ops []StackOp
		ops = append(ops, pushBigInt(bn254FieldP))
		for _, v := range scalars {
			ops = append(ops, pushBigInt(big.NewInt(int64(v))))
		}
		ops = append(ops, pushBigInt(piX), pushBigInt(piY))

		initNames := []string{
			"_qbot_p",
			"_pub_0", "_pub_1", "_pub_2", "_pub_3", "_pub_4",
			"_pi_x", "_pi_y",
		}
		var bind []StackOp
		tracker := NewBN254Tracker(initNames, func(op StackOp) { bind = append(bind, op) })
		tracker.qAtBottom = true
		tracker.primeCacheActive = true
		emitWAGroth16MSMBind(tracker, config)
		for len(tracker.nm) > 0 {
			tracker.drop()
		}
		bind = append(bind, opcode("OP_1"))
		return append(ops, bind...), bind
	}

	ops, bind := build(pub, expX, expY)

	if n := countOpcode(bind, "OP_0NOTEQUAL"); n != 5-len(pinned) {
		t.Fatalf("expected %d OP_0NOTEQUAL zero-guards (one per unpinned slot), got %d", 5-len(pinned), n)
	}
	if n := countOpcode(bind, "OP_EQUALVERIFY"); n < len(pinned) {
		t.Fatalf("expected at least %d OP_EQUALVERIFY (one per pinned slot), got %d", len(pinned), n)
	}
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("pinned MSM bind rejected the correct prepared_inputs: %v", err)
	}

	// Witness scalar for a pinned slot disagrees with the pinned value.
	wrong := pub
	wrong[0]++
	ops, _ = build(wrong, expX, expY)
	if err := buildAndExecute(t, ops); err == nil {
		t.Fatal("pinned MSM bind accepted a witness scalar that differs from the pinned value")
	}

	// Correct scalars, prepared_inputs for a different statement.
	badX, badY := bn254ComputeKG(t, total+1)
	ops, _ = build(pub, badX, badY)
	if err := buildAndExecute(t, ops); err == nil {
		t.Fatal("pinned MSM bind accepted a prepared_inputs point that is not the folded accumulator")
	}
}

// TestMSMBind_AllSlotsPinnedLeavesNoScalarMul: with every slot pinned the
// entire MSM is folded off-chain; the bind reduces to five equality checks
// and one point comparison.
func TestMSMBind_AllSlotsPinnedLeavesNoScalarMul(t *testing.T) {
	pub := [5]int{7, 11, 0, 13, 0}
	genG := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	config := Groth16Config{
		IC: [6][2]*big.Int{genG, genG, genG, genG, genG, genG},
	}
	for i, v := range pub {
		config.PinnedPublicInputs[i] = big.NewInt(int64(v))
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
	initNames := []string{"_qbot_p", "_pub_0", "_pub_1", "_pub_2", "_pub_3", "_pub_4", "_pi_x", "_pi_y"}
	var bind []StackOp
	tracker := NewBN254Tracker(initNames, func(op StackOp) { bind = append(bind, op) })
	tracker.qAtBottom = true
	tracker.primeCacheActive = true
	emitWAGroth16MSMBind(tracker, config)
	for len(tracker.nm) > 0 {
		tracker.drop()
	}
	bind = append(bind, opcode("OP_1"))

	if n := countOpcode(bind, "OP_0NOTEQUAL"); n != 0 {
		t.Fatalf("all slots pinned, yet %d zero-guards (scalar-mul branches) were emitted", n)
	}
	if n := countOp(bind, "if"); n != 0 {
		t.Fatalf("all slots pinned, yet %d IF branches were emitted", n)
	}
	if err := buildAndExecute(t, append(ops, bind...)); err != nil {
		t.Fatalf("fully pinned MSM bind rejected the correct prepared_inputs: %v", err)
	}
}
