package runar

import (
	"fmt"
	"math/big"
	"sort"
	"strconv"
)

// ---------------------------------------------------------------------------
// Constructor arg extraction
// ---------------------------------------------------------------------------

// readScriptElement reads a Bitcoin Script push data element at the given hex
// offset. Returns the pushed data hex, total hex chars consumed, and the opcode.
func readScriptElement(hexStr string, offset int) (dataHex string, totalHexChars int, opcode int) {
	if offset+2 > len(hexStr) {
		return "", 0, 0
	}
	op, _ := strconv.ParseUint(hexStr[offset:offset+2], 16, 8)
	opcode = int(op)

	if opcode == 0x00 {
		return "", 2, opcode
	}
	if opcode >= 0x01 && opcode <= 0x4b {
		dataLen := opcode * 2
		end := offset + 2 + dataLen
		if end > len(hexStr) {
			end = len(hexStr)
		}
		return hexStr[offset+2 : end], 2 + dataLen, opcode
	}
	if opcode == 0x4c { // OP_PUSHDATA1
		if offset+4 > len(hexStr) {
			return "", 2, opcode
		}
		length, _ := strconv.ParseUint(hexStr[offset+2:offset+4], 16, 8)
		dataLen := int(length) * 2
		end := offset + 4 + dataLen
		if end > len(hexStr) {
			end = len(hexStr)
		}
		return hexStr[offset+4 : end], 4 + dataLen, opcode
	}
	if opcode == 0x4d { // OP_PUSHDATA2
		if offset+6 > len(hexStr) {
			return "", 2, opcode
		}
		lo, _ := strconv.ParseUint(hexStr[offset+2:offset+4], 16, 8)
		hi, _ := strconv.ParseUint(hexStr[offset+4:offset+6], 16, 8)
		length := int(lo) | (int(hi) << 8)
		dataLen := length * 2
		end := offset + 6 + dataLen
		if end > len(hexStr) {
			end = len(hexStr)
		}
		return hexStr[offset+6 : end], 6 + dataLen, opcode
	}
	if opcode == 0x4e { // OP_PUSHDATA4
		if offset+10 > len(hexStr) {
			return "", 2, opcode
		}
		b0, _ := strconv.ParseUint(hexStr[offset+2:offset+4], 16, 8)
		b1, _ := strconv.ParseUint(hexStr[offset+4:offset+6], 16, 8)
		b2, _ := strconv.ParseUint(hexStr[offset+6:offset+8], 16, 8)
		b3, _ := strconv.ParseUint(hexStr[offset+8:offset+10], 16, 8)
		length := int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24)
		dataLen := length * 2
		end := offset + 10 + dataLen
		if end > len(hexStr) {
			end = len(hexStr)
		}
		return hexStr[offset+10 : end], 10 + dataLen, opcode
	}
	// All other opcodes (OP_1..OP_16, etc.)
	return "", 2, opcode
}

// decodeScriptNumber decodes a minimally-encoded Bitcoin Script number from hex.
//
// N-074: a Script number is ARBITRARY PRECISION — Rúnar contracts routinely
// carry 256-bit EC scalars and 1024-bit+ Rabin moduli as plain `bigint`
// constructor args. Accumulating into an int64 wrapped SILENTLY at 9 data bytes
// (|v| >= 2^63), so those values came back wrong and rebuilt a locking script
// that no longer matched chain. The encode side (encodeBigIntScriptNumber) was
// already arbitrary-precision; the asymmetry was the bug.
func decodeScriptNumber(dataHex string) *big.Int {
	if len(dataHex) == 0 {
		return new(big.Int)
	}
	bytes := make([]byte, len(dataHex)/2)
	for i := 0; i < len(dataHex); i += 2 {
		v, _ := strconv.ParseUint(dataHex[i:i+2], 16, 8)
		bytes[i/2] = byte(v)
	}
	negative := (bytes[len(bytes)-1] & 0x80) != 0
	bytes[len(bytes)-1] &= 0x7f

	// Sign-magnitude, little-endian: reverse into big-endian for SetBytes.
	be := make([]byte, len(bytes))
	for i, b := range bytes {
		be[len(bytes)-1-i] = b
	}
	result := new(big.Int).SetBytes(be)
	if result.Sign() == 0 {
		return result
	}
	if negative {
		return result.Neg(result)
	}
	return result
}

// scriptNumberValue narrows a decoded Script number back to int64 whenever it
// fits, so every existing caller that type-asserts `int64` keeps working; only
// values that genuinely cannot be represented surface as *big.Int (which
// encodeArg already handles via encodeBigIntScriptNumber).
func scriptNumberValue(n *big.Int) interface{} {
	if n.IsInt64() {
		return n.Int64()
	}
	return n
}

// interpretScriptElement interprets a script element according to its type.
// abiValueEncoding classifies an ABI type name by how its constructor-slot
// value is encoded in the script. TABLE, not a `case` list: the two spellings
// that were missing from the old switch — the bigint aliases RabinSig /
// RabinPubKey, and the CANONICAL boolean (only the `bool` alias was handled) —
// each silently turned a value into a hex string on the way back off chain.
// Mirrors packages/runar-ir-schema/src/abi-type-encoding.ts, the same table the
// compiler stamps ConstructorSlot.valueEncoding from.
var abiValueEncodings = map[string]string{
	"bigint": "scriptnum",
	"int":    "scriptnum",
	// RabinSig / RabinPubKey are bigint aliases; verifyRabinSig lowers to
	// OP_MOD, which reads its operand as a little-endian sign-magnitude
	// Script number — exactly what bigint gets.
	"RabinSig":    "scriptnum",
	"RabinPubKey": "scriptnum",
	// boolean is canonical; bool is the alias several frontends spell.
	"boolean": "bool",
	"bool":    "bool",
}

// abiValueEncoding returns "scriptnum", "bool", or "data" (the default for
// ByteString and every fixed-width byte type).
func abiValueEncoding(typeName string) string {
	if enc, ok := abiValueEncodings[typeName]; ok {
		return enc
	}
	return "data"
}

func interpretScriptElement(opcode int, dataHex string, typeName string) interface{} {
	switch abiValueEncoding(typeName) {
	case "scriptnum":
		if opcode == 0x00 {
			return int64(0)
		}
		if opcode >= 0x51 && opcode <= 0x60 {
			return int64(opcode - 0x50)
		}
		if opcode == 0x4f {
			return int64(-1)
		}
		return scriptNumberValue(decodeScriptNumber(dataHex))
	case "bool":
		if opcode == 0x00 {
			return false
		}
		if opcode == 0x51 {
			return true
		}
		return dataHex != "00"
	default:
		// S1: a ByteString (or other non-numeric) ctor arg whose 1-byte
		// value was MINIMALDATA-encoded as OP_1..OP_16 / OP_1NEGATE carries
		// no separate data bytes in the script — readScriptElement reports
		// an empty dataHex for these opcodes (they aren't direct pushes or
		// OP_PUSHDATA*). The opcode itself IS the value; reconstruct it
		// instead of forwarding the (empty) dataHex. OP_0 correctly falls
		// through to dataHex (the empty string), matching OP_0's true
		// semantics (pushes [], not a 1-byte 0x00).
		if opcode >= 0x51 && opcode <= 0x60 {
			return fmt.Sprintf("%02x", opcode-0x50)
		}
		if opcode == 0x4f {
			return "81"
		}
		return dataHex
	}
}

// ExtractConstructorArgs extracts constructor argument values from a compiled
// on-chain script. Uses artifact.ConstructorSlots to locate each constructor
// arg at its byte offset, reads the push data, and deserializes according to
// the ABI param type.
func ExtractConstructorArgs(artifact *RunarArtifact, scriptHex string) map[string]interface{} {
	if artifact.ConstructorSlots == nil || len(artifact.ConstructorSlots) == 0 {
		return map[string]interface{}{}
	}

	codeHex := scriptHex
	if artifact.StateFields != nil && len(artifact.StateFields) > 0 {
		opReturnPos := FindLastOpReturn(scriptHex)
		if opReturnPos != -1 {
			codeHex = scriptHex[:opReturnPos]
		}
	}

	// Walk EVERY slot in byte order. A constructor param referenced more than
	// once in the contract body emits one slot per reference, and each
	// occurrence's encoded width contributes to the cumulative offset shift —
	// deduplicating before the walk drops those widths and mis-aligns every
	// later slot on artifacts with repeated references. The VALUE is taken from
	// the first occurrence per param.
	slots := make([]ConstructorSlot, len(artifact.ConstructorSlots))
	copy(slots, artifact.ConstructorSlots)
	sort.Slice(slots, func(i, j int) bool {
		return slots[i].ByteOffset < slots[j].ByteOffset
	})

	result := make(map[string]interface{})
	assigned := make(map[int]bool)
	cumulativeShift := 0

	for _, slot := range slots {
		adjustedHexOffset := (slot.ByteOffset + cumulativeShift) * 2
		dataHex, totalHexChars, opcode := readScriptElement(codeHex, adjustedHexOffset)
		// Template placeholders are exactly 1 byte, so the shift contributed by
		// each occurrence is its encoded width minus that byte.
		cumulativeShift += totalHexChars/2 - 1

		if assigned[slot.ParamIndex] {
			continue
		}
		assigned[slot.ParamIndex] = true
		if slot.ParamIndex >= len(artifact.ABI.Constructor.Params) {
			continue
		}
		param := artifact.ABI.Constructor.Params[slot.ParamIndex]
		result[param.Name] = interpretScriptElement(opcode, dataHex, param.Type)
	}

	return result
}

// ---------------------------------------------------------------------------
// Script matching
// ---------------------------------------------------------------------------

// MatchesArtifact determines whether a given on-chain script was produced from
// the given contract artifact (regardless of what constructor args were used).
func MatchesArtifact(artifact *RunarArtifact, scriptHex string) bool {
	codeHex := scriptHex
	if artifact.StateFields != nil && len(artifact.StateFields) > 0 {
		opReturnPos := FindLastOpReturn(scriptHex)
		if opReturnPos != -1 {
			codeHex = scriptHex[:opReturnPos]
		}
	}

	template := artifact.Script

	if artifact.ConstructorSlots == nil || len(artifact.ConstructorSlots) == 0 {
		return codeHex == template
	}

	// Deduplicate by byteOffset, sorted ascending
	seenOffsets := make(map[int]bool)
	allSlots := make([]ConstructorSlot, len(artifact.ConstructorSlots))
	copy(allSlots, artifact.ConstructorSlots)
	sort.Slice(allSlots, func(i, j int) bool {
		return allSlots[i].ByteOffset < allSlots[j].ByteOffset
	})
	var slots []ConstructorSlot
	for _, slot := range allSlots {
		if !seenOffsets[slot.ByteOffset] {
			seenOffsets[slot.ByteOffset] = true
			slots = append(slots, slot)
		}
	}

	templatePos := 0
	codePos := 0

	for _, slot := range slots {
		slotHexOffset := slot.ByteOffset * 2
		templateSegment := template[templatePos:slotHexOffset]
		if codePos+len(templateSegment) > len(codeHex) {
			return false
		}
		codeSegment := codeHex[codePos : codePos+len(templateSegment)]
		if templateSegment != codeSegment {
			return false
		}
		templatePos = slotHexOffset + 2
		elemOffset := codePos + len(templateSegment)
		_, totalHexChars, _ := readScriptElement(codeHex, elemOffset)
		codePos = elemOffset + totalHexChars
	}

	return template[templatePos:] == codeHex[codePos:]
}
