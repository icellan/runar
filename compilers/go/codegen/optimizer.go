package codegen

import "math/big"

// ---------------------------------------------------------------------------
// Peephole optimizer — runs on Stack IR before emission.
//
// Scans for short sequences of stack operations that can be replaced with
// fewer or cheaper opcodes. Applies rules iteratively until a fixed point
// is reached (no more changes). Mirrors the TypeScript peephole optimizer.
// ---------------------------------------------------------------------------

const maxOptimizationIterations = 100

// OptimizeStackOps applies peephole optimization to a list of stack ops.
func OptimizeStackOps(ops []StackOp) []StackOp {
	// First, recursively optimize nested if-blocks
	current := make([]StackOp, len(ops))
	for i, op := range ops {
		current[i] = optimizeNestedIf(op)
	}

	for iteration := 0; iteration < maxOptimizationIterations; iteration++ {
		result, changed := applyOnePass(current)
		if !changed {
			break
		}
		current = result
	}

	return current
}

func optimizeNestedIf(op StackOp) StackOp {
	if op.Op == "if" {
		optimizedThen := OptimizeStackOps(op.Then)
		var optimizedElse []StackOp
		if len(op.Else) > 0 {
			optimizedElse = OptimizeStackOps(op.Else)
		}
		return StackOp{
			Op:   "if",
			Then: optimizedThen,
			Else: optimizedElse,
		}
	}
	return op
}

func applyOnePass(ops []StackOp) ([]StackOp, bool) {
	var result []StackOp
	changed := false
	i := 0

	for i < len(ops) {
		// Try window-2 rules first
		if i+1 < len(ops) {
			if replacement, ok := matchWindow2(ops[i], ops[i+1]); ok {
				result = append(result, replacement...)
				i += 2
				changed = true
				continue
			}
		}

		result = append(result, ops[i])
		i++
	}

	return result, changed
}

func matchWindow2(a, b StackOp) ([]StackOp, bool) {
	// PUSH x, DROP -> remove both (dead value elimination)
	if a.Op == "push" && b.Op == "drop" {
		return nil, true
	}

	// DUP, DROP -> remove both
	if a.Op == "dup" && b.Op == "drop" {
		return nil, true
	}

	// SWAP, SWAP -> remove both (identity)
	if a.Op == "swap" && b.Op == "swap" {
		return nil, true
	}

	// PUSH 1, OP_ADD -> OP_1ADD
	if isPushBigInt(a, 1) && isOpcodeOp(b, "OP_ADD") {
		return []StackOp{{Op: "opcode", Code: "OP_1ADD"}}, true
	}

	// PUSH 1, OP_SUB -> OP_1SUB
	if isPushBigInt(a, 1) && isOpcodeOp(b, "OP_SUB") {
		return []StackOp{{Op: "opcode", Code: "OP_1SUB"}}, true
	}

	// PUSH 0, OP_ADD -> remove both (x + 0 = x)
	if isPushBigInt(a, 0) && isOpcodeOp(b, "OP_ADD") {
		return nil, true
	}

	// PUSH 0, OP_SUB -> remove both (x - 0 = x)
	if isPushBigInt(a, 0) && isOpcodeOp(b, "OP_SUB") {
		return nil, true
	}

	// OP_NOT, OP_NOT -> remove both (double negation)
	if isOpcodeOp(a, "OP_NOT") && isOpcodeOp(b, "OP_NOT") {
		return nil, true
	}

	// OP_NEGATE, OP_NEGATE -> remove both
	if isOpcodeOp(a, "OP_NEGATE") && isOpcodeOp(b, "OP_NEGATE") {
		return nil, true
	}

	// OP_EQUAL, OP_VERIFY -> OP_EQUALVERIFY
	if isOpcodeOp(a, "OP_EQUAL") && isOpcodeOp(b, "OP_VERIFY") {
		return []StackOp{{Op: "opcode", Code: "OP_EQUALVERIFY"}}, true
	}

	// OP_CHECKSIG, OP_VERIFY -> OP_CHECKSIGVERIFY
	if isOpcodeOp(a, "OP_CHECKSIG") && isOpcodeOp(b, "OP_VERIFY") {
		return []StackOp{{Op: "opcode", Code: "OP_CHECKSIGVERIFY"}}, true
	}

	// OP_NUMEQUAL, OP_VERIFY -> OP_NUMEQUALVERIFY
	if isOpcodeOp(a, "OP_NUMEQUAL") && isOpcodeOp(b, "OP_VERIFY") {
		return []StackOp{{Op: "opcode", Code: "OP_NUMEQUALVERIFY"}}, true
	}

	// OP_CHECKMULTISIG, OP_VERIFY -> OP_CHECKMULTISIGVERIFY
	if isOpcodeOp(a, "OP_CHECKMULTISIG") && isOpcodeOp(b, "OP_VERIFY") {
		return []StackOp{{Op: "opcode", Code: "OP_CHECKMULTISIGVERIFY"}}, true
	}

	// OP_DUP, OP_DROP -> remove both
	if isOpcodeOp(a, "OP_DUP") && isOpcodeOp(b, "OP_DROP") {
		return nil, true
	}

	// OP_OVER, OP_OVER -> OP_2DUP
	if a.Op == "over" && b.Op == "over" {
		return []StackOp{{Op: "opcode", Code: "OP_2DUP"}}, true
	}

	// OP_DROP, OP_DROP -> OP_2DROP
	if a.Op == "drop" && b.Op == "drop" {
		return []StackOp{{Op: "opcode", Code: "OP_2DROP"}}, true
	}

	return nil, false
}

func isPushBigInt(op StackOp, n int64) bool {
	if op.Op != "push" || op.Value.Kind != "bigint" || op.Value.BigInt == nil {
		return false
	}
	return op.Value.BigInt.Cmp(big.NewInt(n)) == 0
}

func isOpcodeOp(op StackOp, code string) bool {
	return op.Op == "opcode" && op.Code == code
}
