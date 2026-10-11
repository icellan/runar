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
			Op:        "if",
			Then:      optimizedThen,
			Else:      optimizedElse,
			SourceLoc: op.SourceLoc,
		}
	}
	return op
}

// withHeadSourceLoc gives every replacement op that has no location of its
// own the location of the first op of the matched window (F-179; the TS,
// Python and Rust convention), so the emitter still maps the fused /
// rewritten opcode to its statement.
func withHeadSourceLoc(head StackOp, replacement []StackOp) []StackOp {
	if head.SourceLoc == nil {
		return replacement
	}
	for i := range replacement {
		if replacement[i].SourceLoc == nil {
			replacement[i].SourceLoc = head.SourceLoc
		}
	}
	return replacement
}

func applyOnePass(ops []StackOp) ([]StackOp, bool) {
	var result []StackOp
	changed := false
	i := 0

	for i < len(ops) {
		// Try 4-op window
		if i+3 < len(ops) {
			if replacement, ok := matchWindow4(ops[i], ops[i+1], ops[i+2], ops[i+3]); ok {
				result = append(result, withHeadSourceLoc(ops[i], replacement)...)
				i += 4
				changed = true
				continue
			}
		}
		// Try 3-op window
		if i+2 < len(ops) {
			if replacement, ok := matchWindow3(ops[i], ops[i+1], ops[i+2]); ok {
				result = append(result, withHeadSourceLoc(ops[i], replacement)...)
				i += 3
				changed = true
				continue
			}
		}
		// Try 2-op window
		if i+1 < len(ops) {
			if replacement, ok := matchWindow2(ops[i], ops[i+1]); ok {
				result = append(result, withHeadSourceLoc(ops[i], replacement)...)
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

// isRawBytes reports whether an op is an opaque raw_bytes span emitted by a
// raw_script ANF node. raw_bytes is a hard peephole barrier — no optimization
// window may span or rewrite across it, because the bytes are opaque and not
// guaranteed to form a well-formed opcode stream.
func isRawBytes(op StackOp) bool {
	return op.Op == "raw_bytes"
}

func matchWindow2(a, b StackOp) ([]StackOp, bool) {
	if isRawBytes(a) || isRawBytes(b) {
		return nil, false
	}

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

	// NOTE (F-001): no `PUSH 0, OP_ADD`, `PUSH 0, OP_SUB` or
	// `OP_NEGATE, OP_NEGATE` elimination. x+0, x-0 and -(-x) are identities
	// over integers, not over stack elements: the opcode decodes its operand
	// as a CScriptNum (rejecting a non-minimal encoding under strict rules)
	// and pushes back the minimal re-encoding. Deleting it changes
	// accept/reject and the value for a witness-supplied operand.

	// NOTE: `OP_NOT, OP_NOT` is NOT eliminated here — see the guarded 3-op
	// rule in matchWindow3 (C17). The pair is boolean normalisation, not
	// numeric identity, so it may only be dropped when the producer of the
	// negated value provably leaves a canonical 0/1 behind.

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
	if isPushBigInt(a, 0) && b.Op == "roll" && b.Depth == 0 {
		return nil, true
	}

	// PUSH(1n) + Roll{depth:1} -> SWAP
	if isPushBigInt(a, 1) && b.Op == "roll" && b.Depth == 1 {
		return []StackOp{{Op: "swap"}}, true
	}

	// PUSH(2n) + Roll{depth:2} -> ROT
	if isPushBigInt(a, 2) && b.Op == "roll" && b.Depth == 2 {
		return []StackOp{{Op: "rot"}}, true
	}

	// PUSH(0n) + Pick{depth:0} -> DUP
	if isPushBigInt(a, 0) && b.Op == "pick" && b.Depth == 0 {
		return []StackOp{{Op: "dup"}}, true
	}

	// PUSH(1n) + Pick{depth:1} -> OVER
	if isPushBigInt(a, 1) && b.Op == "pick" && b.Depth == 1 {
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

// canonicalBoolOpcodes are the opcodes whose result is guaranteed to be a
// CANONICAL boolean — the minimal script-number encoding of 0 (the empty
// element) or 1 ({0x01}), and nothing else. Every entry pushes
// CScriptNum(0|1).getvch() (or vchFalse/vchTrue) in the reference interpreter.
//
// Stack-shuffling ops (OP_DUP / OP_PICK / OP_ROLL / OP_SWAP / …) are
// deliberately absent: they forward a value whose provenance this local window
// cannot see.
var canonicalBoolOpcodes = map[string]bool{
	"OP_EQUAL":              true,
	"OP_NUMEQUAL":           true,
	"OP_NUMNOTEQUAL":        true,
	"OP_LESSTHAN":           true,
	"OP_GREATERTHAN":        true,
	"OP_LESSTHANOREQUAL":    true,
	"OP_GREATERTHANOREQUAL": true,
	"OP_BOOLAND":            true,
	"OP_BOOLOR":             true,
	"OP_WITHIN":             true,
	"OP_NOT":                true,
	"OP_0NOTEQUAL":          true,
	"OP_CHECKSIG":           true,
	"OP_CHECKMULTISIG":      true,
}

// producesCanonicalBool reports whether op provably leaves a canonical boolean
// (0 or 1) on the stack.
func producesCanonicalBool(op StackOp) bool {
	if op.Op == "opcode" {
		return canonicalBoolOpcodes[op.Code]
	}
	if op.Op == "push" {
		switch op.Value.Kind {
		case "bool":
			return true
		case "bigint":
			return isPushBigInt(op, 0) || isPushBigInt(op, 1)
		}
	}
	return false
}

func matchWindow3(a, b, c StackOp) ([]StackOp, bool) {
	if isRawBytes(a) || isRawBytes(b) || isRawBytes(c) {
		return nil, false
	}

	// <canonical-bool producer>, OP_NOT, OP_NOT -> <canonical-bool producer>
	//
	// `OP_NOT OP_NOT` is boolean NORMALISATION, not numeric identity: for any
	// non-canonical operand (say 5) the pair yields 1, while deleting it leaves
	// 5. Truthiness is preserved, the VALUE is not — and a downstream OP_EQUAL /
	// OP_NUMEQUAL / state serialisation consumes the value, so the two programs
	// disagree on accept/reject.
	//
	// The window therefore includes the PRODUCER of the value being negated and
	// only fires when that producer provably yields a canonical 0/1 (C17). This
	// matters because the `PUSH 0; OP_NUMEQUAL -> OP_NOT` rule in matchWindow2
	// synthesises a fresh OP_NOT sitting on top of an ARBITRARY script number:
	// for `x !== 0n` the lowerer emits `<x>; PUSH 0; OP_NUMEQUAL; OP_NOT`, which
	// an unguarded 2-op rule collapsed all the way down to `<x>`. With the guard
	// the pair survives as `<x>; OP_NOT; OP_NOT` — still one byte shorter than
	// the input, and value-exact.
	if producesCanonicalBool(a) && isOpcodeOp(b, "OP_NOT") && isOpcodeOp(c, "OP_NOT") {
		return []StackOp{a}, true
	}

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

	// OVER + OVER + OP_ADD -> DUP + OP_2MUL (2x of TOS-1)
	// Wait, OVER OVER gives copies of TOS-1 and TOS-1, not TOS and TOS-1.
	// Actually OVER OVER = [a, b, a, b] which is OP_2DUP (already handled).

	// ROT + ROT + DROP -> NIP + SWAP
	// [a, b, c] -> ROT -> [b, c, a] -> ROT -> [c, a, b] -> DROP -> [c, a]
	// = NIP -> [a, c] -> SWAP -> [c, a]  -- same 2 ops, no savings.

	return nil, false
}

func matchWindow4(a, b, c, d StackOp) ([]StackOp, bool) {
	if isRawBytes(a) || isRawBytes(b) || isRawBytes(c) || isRawBytes(d) {
		return nil, false
	}

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
