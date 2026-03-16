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
		// Try 4-op window
		if i+3 < len(ops) {
			if replacement, ok := matchWindow4(ops[i], ops[i+1], ops[i+2], ops[i+3]); ok {
				result = append(result, replacement...)
				i += 4
				changed = true
				continue
			}
		}
		// Try 3-op window
		if i+2 < len(ops) {
			if replacement, ok := matchWindow3(ops[i], ops[i+1], ops[i+2]); ok {
				result = append(result, replacement...)
				i += 3
				changed = true
				continue
			}
		}
		// Try 2-op window
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

	// PUSH(0n) + Roll{depth:0} -> remove both (roll 0 is a no-op)
	if isPushBigInt(a, 0) && b.Op == "roll" {
		return nil, true
	}

	// PUSH(1n) + Roll{depth:1} -> SWAP
	if isPushBigInt(a, 1) && b.Op == "roll" {
		return []StackOp{{Op: "swap"}}, true
	}

	// PUSH(2n) + Roll{depth:2} -> ROT
	if isPushBigInt(a, 2) && b.Op == "roll" && b.Depth == 2 {
		return []StackOp{{Op: "rot"}}, true
	}

	// PUSH(0n) + Pick{depth:0} -> DUP
	if isPushBigInt(a, 0) && b.Op == "pick" {
		return []StackOp{{Op: "dup"}}, true
	}

	// PUSH(1n) + Pick{depth:1} -> OVER
	if isPushBigInt(a, 1) && b.Op == "pick" {
		return []StackOp{{Op: "over"}}, true
	}

	// SHA256 + SHA256 -> HASH256
	if isOpcodeOp(a, "OP_SHA256") && isOpcodeOp(b, "OP_SHA256") {
		return []StackOp{{Op: "opcode", Code: "OP_HASH256"}}, true
	}

	// PUSH 0 + NUMEQUAL -> NOT
	if isPushBigInt(a, 0) && isOpcodeOp(b, "OP_NUMEQUAL") {
		return []StackOp{{Op: "opcode", Code: "OP_NOT"}}, true
	}

	return nil, false
}

// pushBigIntValue extracts the big.Int from a push op, or returns nil.
func pushBigIntValue(op StackOp) *big.Int {
	if op.Op != "push" || op.Value.Kind != "bigint" || op.Value.BigInt == nil {
		return nil
	}
	return op.Value.BigInt
}

// makePushBigInt creates a push StackOp with the given big.Int value.
func makePushBigInt(n *big.Int) StackOp {
	return StackOp{
		Op: "push",
		Value: PushValue{
			Kind:   "bigint",
			BigInt: n,
		},
	}
}

func matchWindow3(a, b, c StackOp) ([]StackOp, bool) {
	aVal := pushBigIntValue(a)
	bVal := pushBigIntValue(b)

	if aVal != nil && bVal != nil {
		// PUSH(a) + PUSH(b) + OP_ADD -> PUSH(a+b)
		if isOpcodeOp(c, "OP_ADD") {
			result := new(big.Int).Add(aVal, bVal)
			return []StackOp{makePushBigInt(result)}, true
		}
		// PUSH(a) + PUSH(b) + OP_SUB -> PUSH(a-b)
		if isOpcodeOp(c, "OP_SUB") {
			result := new(big.Int).Sub(aVal, bVal)
			return []StackOp{makePushBigInt(result)}, true
		}
		// PUSH(a) + PUSH(b) + OP_MUL -> PUSH(a*b)
		if isOpcodeOp(c, "OP_MUL") {
			result := new(big.Int).Mul(aVal, bVal)
			return []StackOp{makePushBigInt(result)}, true
		}
	}

	return nil, false
}

func matchWindow4(a, b, c, d StackOp) ([]StackOp, bool) {
	aVal := pushBigIntValue(a)
	cVal := pushBigIntValue(c)

	if aVal != nil && cVal != nil {
		// PUSH(a) + OP_ADD + PUSH(b) + OP_ADD -> PUSH(a+b), OP_ADD
		if isOpcodeOp(b, "OP_ADD") && isOpcodeOp(d, "OP_ADD") {
			result := new(big.Int).Add(aVal, cVal)
			return []StackOp{makePushBigInt(result), {Op: "opcode", Code: "OP_ADD"}}, true
		}
		// PUSH(a) + OP_SUB + PUSH(b) + OP_SUB -> PUSH(a+b), OP_SUB
		if isOpcodeOp(b, "OP_SUB") && isOpcodeOp(d, "OP_SUB") {
			result := new(big.Int).Add(aVal, cVal)
			return []StackOp{makePushBigInt(result), {Op: "opcode", Code: "OP_SUB"}}, true
		}
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
