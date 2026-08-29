package codegen

import "math/big"

// Script-byte cost model for Stack IR.
//
// Port of packages/runar-compiler/src/metrics/cost-model.ts. Optimizer passes
// need to compare two candidate lowerings by the metric that actually matters —
// serialized locking-script bytes — before either one is emitted. OP_DUP and a
// 33-byte constant push are one instruction each and 1 vs 34 bytes; an
// instruction count cannot tell them apart.
//
// This is deliberately NOT an approximation: every push routes through the same
// encoders emit.go uses, so
//
//	EstimateScriptBytes(ops) == len(emitted hex) / 2
//
// holds exactly. cost_model_test.go asserts that over the conformance corpus.

// SizeOfPushValue returns the serialized byte cost of a single push value.
//
// Mirrors encodePushValue in emit.go: booleans are the 1-byte OP_TRUE /
// OP_FALSE, big.Ints go through the small-int opcodes where possible, and byte
// slices are MINIMALDATA-aware before falling back to a length-prefixed push.
func SizeOfPushValue(value PushValue) int {
	hexStr, _ := encodePushValue(value)
	return len(hexStr) / 2
}

// SizeOfPushBigInt is SizeOfPushValue for a bare integer, which is what the
// constant pool and the comb width search compare against.
func SizeOfPushBigInt(n *big.Int) int {
	hexStr, _ := encodePushBigInt(n)
	return len(hexStr) / 2
}

// SizeOfStackOp returns the serialized byte cost of one Stack IR operation,
// including nested if arms.
//
// Note on pick / roll: they cost ONE byte here. The depth operand is a separate
// push op that the lowerer emits immediately before, so charging the depth here
// would double-count it.
//
// Panics on an unknown opcode mnemonic rather than costing it zero — a typo in
// a codegen module should surface loudly, not as a cost model that quietly
// under-reports.
func SizeOfStackOp(op StackOp) int {
	switch op.Op {
	case "push":
		return SizeOfPushValue(op.Value)

	case "dup", "swap", "roll", "pick", "drop", "nip", "over", "rot", "tuck":
		return 1

	case "opcode":
		if _, ok := opcodes[op.Code]; !ok {
			panic("cost-model: unknown opcode '" + op.Code + "'")
		}
		return 1

	case "if":
		// OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
		// OP_ELSE only for a NON-EMPTY else arm.
		total := 2
		total += EstimateScriptBytes(op.Then)
		if len(op.Else) > 0 {
			total += 1 + EstimateScriptBytes(op.Else)
		}
		return total

	case "placeholder", "push_codesep_index":
		// Both emit a single 0x00 byte that the SDK rewrites later.
		return 1

	case "raw_bytes":
		return len(op.RawBytes)
	}
	panic("cost-model: unknown stack op kind '" + op.Op + "'")
}

// EstimateScriptBytes returns the serialized byte cost of a Stack IR sequence.
func EstimateScriptBytes(ops []StackOp) int {
	total := 0
	for _, op := range ops {
		total += SizeOfStackOp(op)
	}
	return total
}
