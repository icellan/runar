package analyzer

import "fmt"

// stackEffect returns the conservative (pops, pushes) for an opcode
// per §8.1.
func stackEffect(op Opcode) (int, int) {
	if op.IsRawSpan {
		return op.RawSpanArity[0], op.RawSpanArity[1]
	}
	if op.PushEncoding != "" {
		// All push-style ops: (0, 1).
		return 0, 1
	}
	switch byte(op.Opcode) {
	case 0x61: // OP_NOP
		return 0, 0
	case 0x63, 0x64: // OP_IF, OP_NOTIF
		return 1, 0
	case 0x67, 0x68: // OP_ELSE, OP_ENDIF
		return 0, 0
	case 0x69: // OP_VERIFY
		return 1, 0
	case 0x6a: // OP_RETURN
		return 0, 0
	case 0x6b: // OP_TOALTSTACK
		return 1, 0
	case 0x6c: // OP_FROMALTSTACK
		return 0, 1
	case 0x6d: // OP_2DROP
		return 2, 0
	case 0x6e: // OP_2DUP
		return 2, 4
	case 0x6f: // OP_3DUP
		return 3, 6
	case 0x70: // OP_2OVER
		return 4, 6
	case 0x71: // OP_2ROT
		return 6, 6
	case 0x72: // OP_2SWAP
		return 4, 4
	case 0x73: // OP_IFDUP
		return 1, 1
	case 0x74: // OP_DEPTH
		return 0, 1
	case 0x75: // OP_DROP
		return 1, 0
	case 0x76: // OP_DUP
		return 1, 2
	case 0x77: // OP_NIP
		return 2, 1
	case 0x78: // OP_OVER
		return 2, 3
	case 0x79: // OP_PICK
		return 1, 1
	case 0x7a: // OP_ROLL
		return 1, 0
	case 0x7b: // OP_ROT
		return 3, 3
	case 0x7c: // OP_SWAP
		return 2, 2
	case 0x7d: // OP_TUCK
		return 2, 3
	case 0x7e: // OP_CAT
		return 2, 1
	case 0x7f: // OP_SPLIT
		return 2, 2
	case 0x80: // OP_NUM2BIN
		return 2, 1
	case 0x81: // OP_BIN2NUM
		return 1, 1
	case 0x82: // OP_SIZE
		return 1, 2
	case 0x83: // OP_INVERT
		return 1, 1
	case 0x84, 0x85, 0x86: // OP_AND, OP_OR, OP_XOR
		return 2, 1
	case 0x87: // OP_EQUAL
		return 2, 1
	case 0x88: // OP_EQUALVERIFY
		return 2, 0
	case 0x8b, 0x8c: // OP_1ADD, OP_1SUB
		return 1, 1
	case 0x8f, 0x90, 0x91, 0x92: // NEGATE, ABS, NOT, 0NOTEQUAL
		return 1, 1
	case 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
		0x9a, 0x9b, 0x9c:
		return 2, 1
	case 0x9d: // OP_NUMEQUALVERIFY
		return 2, 0
	case 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4:
		return 2, 1
	case 0xa5: // OP_WITHIN
		return 3, 1
	case 0xa6, 0xa7, 0xa8, 0xa9, 0xaa: // RIPEMD160..HASH256
		return 1, 1
	case 0xac: // OP_CHECKSIG
		return 2, 1
	case 0xad: // OP_CHECKSIGVERIFY
		return 2, 0
	case 0xae: // OP_CHECKMULTISIG
		return 3, 1
	case 0xaf: // OP_CHECKMULTISIGVERIFY
		return 3, 0
	}
	return 0, 0
}

// flatDelta sums pushes-pops over a half-open opcode range [lo, hi).
// Returns (delta, ok). ok is false if the range contains a nested
// OP_IF/OP_NOTIF (undefined per §7.6).
func flatDelta(ops []Opcode, lo, hi int) (int, bool) {
	delta := 0
	for i := lo; i < hi; i++ {
		if ops[i].IsRawSpan {
			delta += ops[i].RawSpanArity[1] - ops[i].RawSpanArity[0]
			continue
		}
		b := byte(ops[i].Opcode)
		if b == opIf || b == opNotIf {
			return 0, false
		}
		if b == opElse || b == opEndIf {
			continue
		}
		pops, pushes := stackEffect(ops[i])
		delta += pushes - pops
	}
	return delta, true
}

// linearAnalysisResult is the per-path stack outcome.
type linearAnalysisResult struct {
	depth     int
	maxDepth  int
	findings  []Finding
}

// analyzeStackLinear executes §8.2 over a flat opcode sequence.
func analyzeStackLinear(ops []Opcode, initialDepth int) linearAnalysisResult {
	res := linearAnalysisResult{depth: initialDepth, maxDepth: initialDepth}
	afterReturn := false
	for _, op := range ops {
		if afterReturn {
			res.findings = append(res.findings, Finding{
				Severity:  SeverityWarning,
				Code:      "UNREACHABLE_AFTER_RETURN",
				Message:   fmt.Sprintf("Unreachable opcode %s after OP_RETURN", op.Name),
				Offset:    op.Offset,
				HasOffset: true,
				Opcode:    op.Name,
				HasOpcode: true,
			})
			continue
		}
		if !op.IsRawSpan && byte(op.Opcode) == opReturn {
			afterReturn = true
			continue
		}
		pops, pushes := stackEffect(op)
		if initialDepth > 0 && res.depth < pops {
			res.findings = append(res.findings, Finding{
				Severity:  SeverityError,
				Code:      "STACK_UNDERFLOW",
				Message:   fmt.Sprintf("%s requires %d stack item(s) but only %d available", op.Name, pops, res.depth),
				Offset:    op.Offset,
				HasOffset: true,
				Opcode:    op.Name,
				HasOpcode: true,
			})
		}
		res.depth = res.depth - pops + pushes
		if res.depth > res.maxDepth {
			res.maxDepth = res.depth
		}
	}
	return res
}
