package analyzer

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// opcodeNames is the canonical name table for §4. Anything not present
// renders as OP_UNKNOWN(0xNN).
var opcodeNames = map[byte]string{
	0x00: "OP_0",
	0x4c: "OP_PUSHDATA1",
	0x4d: "OP_PUSHDATA2",
	0x4e: "OP_PUSHDATA4",
	0x4f: "OP_1NEGATE",
	0x51: "OP_1", 0x52: "OP_2", 0x53: "OP_3", 0x54: "OP_4",
	0x55: "OP_5", 0x56: "OP_6", 0x57: "OP_7", 0x58: "OP_8",
	0x59: "OP_9", 0x5a: "OP_10", 0x5b: "OP_11", 0x5c: "OP_12",
	0x5d: "OP_13", 0x5e: "OP_14", 0x5f: "OP_15", 0x60: "OP_16",

	0x61: "OP_NOP",
	0x63: "OP_IF", 0x64: "OP_NOTIF",
	0x67: "OP_ELSE", 0x68: "OP_ENDIF",
	0x69: "OP_VERIFY", 0x6a: "OP_RETURN",
	0x6b: "OP_TOALTSTACK", 0x6c: "OP_FROMALTSTACK",
	0x6d: "OP_2DROP", 0x6e: "OP_2DUP", 0x6f: "OP_3DUP",
	0x70: "OP_2OVER", 0x71: "OP_2ROT", 0x72: "OP_2SWAP",
	0x73: "OP_IFDUP", 0x74: "OP_DEPTH",
	0x75: "OP_DROP", 0x76: "OP_DUP",
	0x77: "OP_NIP", 0x78: "OP_OVER",
	0x79: "OP_PICK", 0x7a: "OP_ROLL", 0x7b: "OP_ROT",
	0x7c: "OP_SWAP", 0x7d: "OP_TUCK",
	0x7e: "OP_CAT", 0x7f: "OP_SPLIT",
	0x80: "OP_NUM2BIN", 0x81: "OP_BIN2NUM",
	0x82: "OP_SIZE",
	0x83: "OP_INVERT", 0x84: "OP_AND", 0x85: "OP_OR", 0x86: "OP_XOR",
	0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
	0x8b: "OP_1ADD", 0x8c: "OP_1SUB",
	0x8f: "OP_NEGATE", 0x90: "OP_ABS",
	0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL",
	0x93: "OP_ADD", 0x94: "OP_SUB",
	0x95: "OP_MUL", 0x96: "OP_DIV", 0x97: "OP_MOD",
	0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT",
	0x9a: "OP_BOOLAND", 0x9b: "OP_BOOLOR",
	0x9c: "OP_NUMEQUAL", 0x9d: "OP_NUMEQUALVERIFY", 0x9e: "OP_NUMNOTEQUAL",
	0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN",
	0xa1: "OP_LESSTHANOREQUAL", 0xa2: "OP_GREATERTHANOREQUAL",
	0xa3: "OP_MIN", 0xa4: "OP_MAX", 0xa5: "OP_WITHIN",
	0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1", 0xa8: "OP_SHA256",
	0xa9: "OP_HASH160", 0xaa: "OP_HASH256",
	0xab: "OP_CODESEPARATOR",
	0xac: "OP_CHECKSIG", 0xad: "OP_CHECKSIGVERIFY",
	0xae: "OP_CHECKMULTISIG", 0xaf: "OP_CHECKMULTISIGVERIFY",
}

// opcodeName returns the canonical name for a raw byte.
func opcodeName(b byte) string {
	if n, ok := opcodeNames[b]; ok {
		return n
	}
	return fmt.Sprintf("OP_UNKNOWN(0x%02x)", b)
}

// normalizeHex strips whitespace and lowercases.
func normalizeHex(hexScript string) string {
	var b strings.Builder
	b.Grow(len(hexScript))
	for _, r := range hexScript {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			continue
		}
		// Lowercase: only A-F → a-f, everything else passes through.
		if r >= 'A' && r <= 'F' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// parseScript consumes a normalized lowercase hex string and produces
// the opcode list. Truncated pushes are emitted with whatever data is
// available; parsing then stops. See §6.1.
func parseScript(normalizedHex string) ([]Opcode, error) {
	if len(normalizedHex)%2 != 0 {
		return nil, fmt.Errorf("hex length %d is odd", len(normalizedHex))
	}
	raw, err := hex.DecodeString(normalizedHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	var out []Opcode
	i := 0
	for i < len(raw) {
		b := raw[i]
		op := Opcode{Offset: i, Opcode: int(b), Name: opcodeName(b)}

		switch {
		case b >= 0x01 && b <= 0x4b:
			// Direct push: opcode byte is data length.
			dataLen := int(b)
			start := i + 1
			end := start + dataLen
			if end > len(raw) {
				end = len(raw)
			}
			op.Data = raw[start:end]
			op.Size = 1 + dataLen
			op.PushEncoding = "direct"
			op.Name = fmt.Sprintf("PUSH_%d", dataLen)
			out = append(out, op)
			if end < start+dataLen {
				return out, nil
			}
			i += 1 + dataLen
		case b == 0x4c:
			// PUSHDATA1: next byte = length.
			if i+1 >= len(raw) {
				op.Size = len(raw) - i
				op.PushEncoding = "pushdata1"
				out = append(out, op)
				return out, nil
			}
			dataLen := int(raw[i+1])
			start := i + 2
			end := start + dataLen
			if end > len(raw) {
				end = len(raw)
			}
			op.Data = raw[start:end]
			op.Size = 2 + dataLen
			op.PushEncoding = "pushdata1"
			out = append(out, op)
			if end < start+dataLen {
				return out, nil
			}
			i += 2 + dataLen
		case b == 0x4d:
			// PUSHDATA2: next 2 bytes LE = length.
			if i+2 >= len(raw) {
				op.Size = len(raw) - i
				op.PushEncoding = "pushdata2"
				out = append(out, op)
				return out, nil
			}
			dataLen := int(raw[i+1]) | int(raw[i+2])<<8
			start := i + 3
			end := start + dataLen
			if end > len(raw) {
				end = len(raw)
			}
			op.Data = raw[start:end]
			op.Size = 3 + dataLen
			op.PushEncoding = "pushdata2"
			out = append(out, op)
			if end < start+dataLen {
				return out, nil
			}
			i += 3 + dataLen
		case b == 0x4e:
			// PUSHDATA4: next 4 bytes LE = length.
			if i+4 >= len(raw) {
				op.Size = len(raw) - i
				op.PushEncoding = "pushdata4"
				out = append(out, op)
				return out, nil
			}
			dataLen := int(raw[i+1]) | int(raw[i+2])<<8 | int(raw[i+3])<<16 | int(raw[i+4])<<24
			start := i + 5
			end := start + dataLen
			if end > len(raw) {
				end = len(raw)
			}
			op.Data = raw[start:end]
			op.Size = 5 + dataLen
			op.PushEncoding = "pushdata4"
			out = append(out, op)
			if end < start+dataLen {
				return out, nil
			}
			i += 5 + dataLen
		case b == 0x00 || b == 0x4f || (b >= 0x51 && b <= 0x60):
			op.Size = 1
			op.PushEncoding = "opN"
			out = append(out, op)
			i++
		default:
			op.Size = 1
			out = append(out, op)
			i++
		}
	}
	return out, nil
}

// collapseRawScriptSpans implements §12. It returns a new opcode list
// in which every opcode whose byte range lies inside a span is
// replaced by a single synthetic RAW_SPAN step.
func collapseRawScriptSpans(opcodes []Opcode, spans []RawScriptSpan) []Opcode {
	if len(spans) == 0 {
		return opcodes
	}
	sorted := make([]RawScriptSpan, len(spans))
	copy(sorted, spans)
	// Insertion sort is fine — spans are small.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1].Offset > sorted[j].Offset; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}

	out := make([]Opcode, 0, len(opcodes))
	spanIdx := 0

	emitRawSpan := func(span RawScriptSpan) {
		if len(out) > 0 {
			last := out[len(out)-1]
			if last.IsRawSpan && last.Offset == span.Offset {
				return
			}
		}
		out = append(out, Opcode{
			Offset:       span.Offset,
			Opcode:       -1,
			Name:         "RAW_SPAN",
			Size:         span.Length,
			IsRawSpan:    true,
			RawSpanArity: [2]int{span.InArity, span.OutArity},
		})
	}

	for _, op := range opcodes {
		for spanIdx < len(sorted) && sorted[spanIdx].Offset+sorted[spanIdx].Length <= op.Offset {
			spanIdx++
		}
		if spanIdx >= len(sorted) {
			out = append(out, op)
			continue
		}
		span := sorted[spanIdx]
		spanEnd := span.Offset + span.Length
		if op.Offset+op.Size <= span.Offset {
			out = append(out, op)
			continue
		}
		if op.Offset >= span.Offset && op.Offset+op.Size <= spanEnd {
			emitRawSpan(span)
			continue
		}
		// Partial overlap: drop and emit synthetic once.
		emitRawSpan(span)
	}
	return out
}
