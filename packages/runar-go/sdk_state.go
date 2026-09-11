package runar

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// State serialization — encode/decode state values as Bitcoin Script push data
// ---------------------------------------------------------------------------

// SerializeState encodes a set of state values into a hex-encoded Bitcoin
// Script data section (without the OP_RETURN prefix). Field order is
// determined by the Index property of each StateField.
//
// Fields with a `FixedArray` annotation are expanded into N element
// writes in declaration order. Callers may supply either a nested
// (possibly multi-dim) Go slice on the grouped name
// (`values["board"] = []interface{}{...}`) or the underlying scalar
// fields (`values["board__0"] = ...`) — scalars win if both are
// present, for backward compatibility.
func SerializeState(fields []StateField, values map[string]interface{}) string {
	sorted := make([]StateField, len(fields))
	copy(sorted, fields)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Index < sorted[j].Index
	})

	var hex strings.Builder
	for _, field := range sorted {
		if field.FixedArray != nil {
			arr := values[field.Name]
			names := field.FixedArray.SyntheticNames
			// Peel off every FixedArray layer from the declared type
			// to find the leaf scalar type that encodeStateValue knows
			// how to serialise.
			leafType := unwrapFixedArrayLeaf(field.Type)
			dims := parseFixedArrayDims(field.Type)
			var flatFromArr []interface{}
			if arr != nil {
				flatFromArr = flattenNestedValue(arr, dims)
			}
			for i := 0; i < len(names); i++ {
				var elem interface{}
				if v, ok := values[names[i]]; ok {
					elem = v
				} else if flatFromArr != nil && i < len(flatFromArr) {
					elem = flatFromArr[i]
				}
				hex.WriteString(encodeStateValue(elem, leafType, names[i]))
			}
		} else {
			value := values[field.Name]
			hex.WriteString(encodeStateValue(value, field.Type, field.Name))
		}
	}
	return hex.String()
}

// DeserializeState decodes state values from a hex-encoded Bitcoin Script
// data section. The caller must strip the code prefix and OP_RETURN byte
// before passing the data section.
//
// Fields with a `FixedArray` annotation are returned as a nested Go
// slice (`[]interface{}`) on the grouped name, not as N individual
// scalar fields.
func DeserializeState(fields []StateField, scriptHex string) map[string]interface{} {
	sorted := make([]StateField, len(fields))
	copy(sorted, fields)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Index < sorted[j].Index
	})

	result := make(map[string]interface{})
	offset := 0

	for _, field := range sorted {
		if field.FixedArray != nil {
			leafType := unwrapFixedArrayLeaf(field.Type)
			dims := parseFixedArrayDims(field.Type)
			total := len(field.FixedArray.SyntheticNames)
			flat := make([]interface{}, total)
			for i := 0; i < total; i++ {
				value, bytesRead := decodeStateValue(scriptHex, offset, leafType)
				flat[i] = value
				offset += bytesRead
			}
			result[field.Name] = regroupNestedValue(flat, dims)
		} else {
			value, bytesRead := decodeStateValue(scriptHex, offset, field.Type)
			result[field.Name] = value
			offset += bytesRead
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// FixedArray type-string helpers — mirror TS SDK/state.ts parseFixedArrayDims
// and unwrapFixedArrayLeaf.
// ---------------------------------------------------------------------------

// parseFixedArrayDims parses a nested `FixedArray<...>` type string
// into its outer dimensions:
//
//	"FixedArray<bigint, 9>"                          -> [9]
//	"FixedArray<FixedArray<bigint, 2>, 3>"           -> [3, 2]
//	"FixedArray<FixedArray<FixedArray<bigint,2>,3>,4>" -> [4, 3, 2]
//
// Non-FixedArray types return an empty slice.
func parseFixedArrayDims(t string) []int {
	var dims []int
	current := strings.TrimSpace(t)
	for strings.HasPrefix(current, "FixedArray<") {
		inner := current[len("FixedArray<") : len(current)-1]
		splitAt := -1
		depth := 0
		for i := len(inner) - 1; i >= 0; i-- {
			ch := inner[i]
			if ch == '>' {
				depth++
			} else if ch == '<' {
				depth--
			} else if ch == ',' && depth == 0 {
				splitAt = i
				break
			}
		}
		if splitAt < 0 {
			return dims
		}
		elemType := strings.TrimSpace(inner[:splitAt])
		lenStr := strings.TrimSpace(inner[splitAt+1:])
		n, err := strconv.Atoi(lenStr)
		if err != nil || n <= 0 {
			return dims
		}
		dims = append(dims, n)
		current = elemType
	}
	return dims
}

// unwrapFixedArrayLeaf returns the innermost scalar type of a
// (possibly nested) FixedArray type string.
func unwrapFixedArrayLeaf(t string) string {
	current := strings.TrimSpace(t)
	for strings.HasPrefix(current, "FixedArray<") {
		inner := current[len("FixedArray<") : len(current)-1]
		splitAt := -1
		depth := 0
		for i := len(inner) - 1; i >= 0; i-- {
			ch := inner[i]
			if ch == '>' {
				depth++
			} else if ch == '<' {
				depth--
			} else if ch == ',' && depth == 0 {
				splitAt = i
				break
			}
		}
		if splitAt < 0 {
			return current
		}
		current = strings.TrimSpace(inner[:splitAt])
	}
	return current
}

// flattenNestedValue flattens a nested Go slice/array of depth
// len(dims) into a flat leaf list. Non-slice inputs are treated as
// absent and return a zero-filled slice of the product of `dims`.
// Mirrors the TS helper.
func flattenNestedValue(value interface{}, dims []int) []interface{} {
	if len(dims) == 0 {
		return []interface{}{value}
	}
	// Normalise `[]interface{}`, `[]int`, `[]int64`, etc.
	elems := asInterfaceSlice(value)
	if elems == nil {
		total := 1
		for _, d := range dims {
			total *= d
		}
		out := make([]interface{}, total)
		return out
	}
	rest := dims[1:]
	var out []interface{}
	for _, v := range elems {
		out = append(out, flattenNestedValue(v, rest)...)
	}
	return out
}

// regroupNestedValue rebuilds a nested `[]interface{}` of depth
// len(dims) from a flat leaf list. Mirrors the TS helper.
func regroupNestedValue(flat []interface{}, dims []int) interface{} {
	if len(dims) == 0 {
		if len(flat) > 0 {
			return flat[0]
		}
		return nil
	}
	v, _ := regroupNestedInner(flat, dims, 0)
	return v
}

func regroupNestedInner(flat []interface{}, dims []int, offset int) (interface{}, int) {
	if len(dims) == 0 {
		return nil, 0
	}
	outerLen := dims[0]
	rest := dims[1:]
	out := make([]interface{}, outerLen)
	consumed := 0
	if len(rest) == 0 {
		for i := 0; i < outerLen; i++ {
			if offset+i < len(flat) {
				out[i] = flat[offset+i]
			}
		}
		consumed = outerLen
	} else {
		for i := 0; i < outerLen; i++ {
			sub, used := regroupNestedInner(flat, rest, offset+consumed)
			out[i] = sub
			consumed += used
		}
	}
	return out, consumed
}

// asInterfaceSlice normalises a value into `[]interface{}`. Accepts
// []interface{}, []int, []int64, []uint, []uint64, []string, and
// []map[string]interface{}; returns nil for non-slice inputs so the
// caller can fall back to zero-fill.
func asInterfaceSlice(value interface{}) []interface{} {
	switch v := value.(type) {
	case []interface{}:
		return v
	case []int:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = x
		}
		return out
	case []int64:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = x
		}
		return out
	case []uint:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = x
		}
		return out
	case []uint64:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = x
		}
		return out
	case []string:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = x
		}
		return out
	}
	return nil
}

// ExtractStateFromScript extracts state values from a full locking script
// hex, given the artifact. Returns nil if the artifact has no state fields
// or the script doesn't contain a recognizable state section.
func ExtractStateFromScript(artifact *RunarArtifact, scriptHex string) map[string]interface{} {
	if artifact.StateFields == nil || len(artifact.StateFields) == 0 {
		return nil
	}

	opReturnPos := FindLastOpReturn(scriptHex)
	if opReturnPos == -1 {
		return nil
	}

	// State data starts after the OP_RETURN byte (2 hex chars)
	stateHex := scriptHex[opReturnPos+2:]
	return DeserializeState(artifact.StateFields, stateHex)
}

// FindLastOpReturn walks the script hex as Bitcoin Script opcodes to find the
// last OP_RETURN (0x6a) at a real opcode boundary. Unlike strings.LastIndex,
// this properly skips push data so it won't match 0x6a bytes inside data
// payloads. Returns the hex-char offset of the last OP_RETURN, or -1.
func FindLastOpReturn(scriptHex string) int {
	lastPos := -1
	offset := 0
	length := len(scriptHex)

	for offset+2 <= length {
		opcode := hexByteValAt(scriptHex, offset)

		if opcode == 0x6a {
			// OP_RETURN at a real opcode boundary. Everything after is
			// raw state data (not opcodes), so stop walking immediately.
			return offset
		} else if opcode >= 0x01 && opcode <= 0x4b {
			// Direct push: opcode is the number of bytes
			offset += 2 + int(opcode)*2
		} else if opcode == 0x4c {
			// OP_PUSHDATA1: next 1 byte is the length
			if offset+4 > length {
				break
			}
			pushLen := hexByteValAt(scriptHex, offset+2)
			offset += 4 + int(pushLen)*2
		} else if opcode == 0x4d {
			// OP_PUSHDATA2: next 2 bytes (LE) are the length
			if offset+6 > length {
				break
			}
			lo := hexByteValAt(scriptHex, offset+2)
			hi := hexByteValAt(scriptHex, offset+4)
			pushLen := int(lo) | (int(hi) << 8)
			offset += 6 + pushLen*2
		} else if opcode == 0x4e {
			// OP_PUSHDATA4: next 4 bytes (LE) are the length
			if offset+10 > length {
				break
			}
			b0 := hexByteValAt(scriptHex, offset+2)
			b1 := hexByteValAt(scriptHex, offset+4)
			b2 := hexByteValAt(scriptHex, offset+6)
			b3 := hexByteValAt(scriptHex, offset+8)
			pushLen := int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24)
			offset += 10 + pushLen*2
		} else {
			// All other opcodes (OP_0, OP_1..16, OP_IF, OP_ADD, etc.)
			offset += 2
		}
	}

	return lastPos
}

func hexByteValAt(hex string, pos int) uint64 {
	if pos+2 > len(hex) {
		return 0
	}
	v, _ := strconv.ParseUint(hex[pos:pos+2], 16, 8)
	return v
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

// encodeStateValue encodes a state field as raw bytes (no push opcode wrapper)
// matching the compiler's OP_NUM2BIN-based fixed-width serialization.
// The result is raw hex bytes that are concatenated after OP_RETURN.
func encodeStateValue(value interface{}, fieldType string, label string) string {
	switch fieldType {
	case "int", "bigint":
		n := stateFieldInt64(value, label, 8)
		return encodeNum2Bin(n, 8)
	case "bool":
		b, _ := value.(bool)
		if b {
			return "01"
		}
		return "00"
	case "PubKey", "Addr", "Ripemd160", "Sha256", "Point", "P256Point", "P384Point":
		// Fixed-size byte types: raw hex, no framing needed.
		// P256Point (64) and P384Point (96) belong here because runar-lang's
		// cast constructors hard-assert those widths and all seven compilers
		// emit them as fixed raw slices; framing them instead deploys a state
		// section 1-2 bytes long and the first spend fails.
		return fmt.Sprintf("%v", value)
	default:
		// Variable-length types (bytes, ByteString, etc.): use push-data
		// encoding so the decoder can determine the length.
		hex := fmt.Sprintf("%v", value)
		if len(hex) == 0 {
			return "00" // OP_0
		}
		return encodePushDataState(hex)
	}
}

// encodePushDataState frames a hex-encoded byte string as a state-section
// field: <len><data>.
//
// This is deliberately NOT the MINIMALDATA push encoding used by
// EncodePushData. The state section is raw data after OP_RETURN in the
// locking script; the interpreter never executes it, so
// SCRIPT_VERIFY_MINIMALDATA — a rule applied to push opcodes as they are
// executed — does not reach it. What does read it is the compiler's on-chain
// state codec (emitPushDataEncode in
// packages/runar-compiler/src/passes/05-stack-lower.ts), which writes and
// parses <len><data>. Both sides must agree byte for byte or the continuation
// hash check fails and the contract is unspendable.
//
// #110 applied the MINIMALDATA short-circuit here, in all seven SDKs and none
// of the seven compilers, so a 1-byte 0x05 state field serialised off-chain as
// "55" while the script rebuilt it as "0105". Byte-identical with the other
// six SDKs.
func encodePushDataState(dataHex string) string {
	dataLen := len(dataHex) / 2

	if dataLen <= 75 {
		return fmt.Sprintf("%02x", dataLen) + dataHex
	} else if dataLen <= 0xff {
		return "4c" + fmt.Sprintf("%02x", dataLen) + dataHex
	} else if dataLen <= 0xffff {
		lo := dataLen & 0xff
		hi := (dataLen >> 8) & 0xff
		return "4d" + fmt.Sprintf("%02x%02x", lo, hi) + dataHex
	}
	b0 := dataLen & 0xff
	b1 := (dataLen >> 8) & 0xff
	b2 := (dataLen >> 16) & 0xff
	b3 := (dataLen >> 24) & 0xff
	return "4e" + fmt.Sprintf("%02x%02x%02x%02x", b0, b1, b2, b3) + dataHex
}

// encodeNum2Bin encodes an integer as a fixed-width LE sign-magnitude byte
// string, matching OP_NUM2BIN behaviour. The sign bit is in the MSB of the
// last byte.
func encodeNum2Bin(n int64, width int) string {
	buf := make([]byte, width)
	negative := n < 0
	absVal := n
	if negative {
		absVal = -absVal
	}
	v := uint64(absVal)
	for i := 0; i < width && v > 0; i++ {
		buf[i] = byte(v & 0xff)
		v >>= 8
	}
	if negative {
		buf[width-1] |= 0x80
	}
	return bytesToHex(buf)
}

// EncodeScriptInt encodes an integer as a Bitcoin Script minimal-encoded
// number push for state serialization. Note: state encoding always uses
// push-data format (even for 0), unlike the contract.ts encoding which
// uses OP_0/OP_1..16 opcodes.
func EncodeScriptInt(n int64) string {
	if n == 0 {
		return "00" // OP_0
	}

	negative := n < 0
	absVal := n
	if negative {
		absVal = -absVal
	}

	var bytes []byte
	uval := uint64(absVal)
	for uval > 0 {
		bytes = append(bytes, byte(uval&0xff))
		uval >>= 8
	}

	// If the high bit of the last byte is set, add a sign byte
	if bytes[len(bytes)-1]&0x80 != 0 {
		if negative {
			bytes = append(bytes, 0x80)
		} else {
			bytes = append(bytes, 0x00)
		}
	} else if negative {
		bytes[len(bytes)-1] |= 0x80
	}

	hex := bytesToHex(bytes)
	return EncodePushData(hex)
}

// EncodePushData wraps a hex-encoded byte string in a Bitcoin Script push
// data opcode.
//
// Applies BSV consensus rule SCRIPT_VERIFY_MINIMALDATA for single-byte
// pushes: a 1-byte payload whose value is in {0x01..=0x10, 0x81} MUST use
// the corresponding minimal opcode (OP_1..OP_16 / OP_1NEGATE) rather than
// the direct push "01 NN". Non-minimal direct pushes are rejected at the
// relay layer with:
//   non-mandatory-script-verify-flag (Data push larger than necessary)
//
// NOTE: 0x00 is deliberately NOT in that set. OP_0 pushes the EMPTY byte
// array, not a 1-byte 0x00 — so the minimal encoding of a 1-byte 0x00
// payload is the direct push "0100" (matching the compiler's
// encodePushBytesHex in push-encoding.ts), not OP_0 (C9 / S1).
func EncodePushData(dataHex string) string {
	dataLen := len(dataHex) / 2

	// MINIMALDATA: single-byte payloads in the OP_N range must use the
	// corresponding minimal opcode. The script-number encoder already
	// short-circuits OP_N for Int fields; this brings the ByteString push
	// path to the same standard so a 1-byte ByteString value does not emit
	// a relay-rejected non-minimal direct push.
	if dataLen == 1 {
		if b, err := strconv.ParseUint(dataHex, 16, 8); err == nil {
			switch {
			case b >= 0x01 && b <= 0x10:
				return fmt.Sprintf("%02x", 0x50+b) // OP_1..OP_16
			case b == 0x81:
				return "4f" // OP_1NEGATE
			}
		}
	}

	if dataLen <= 75 {
		return fmt.Sprintf("%02x", dataLen) + dataHex
	} else if dataLen <= 0xff {
		return "4c" + fmt.Sprintf("%02x", dataLen) + dataHex
	} else if dataLen <= 0xffff {
		lo := dataLen & 0xff
		hi := (dataLen >> 8) & 0xff
		return "4d" + fmt.Sprintf("%02x%02x", lo, hi) + dataHex
	} else {
		b0 := dataLen & 0xff
		b1 := (dataLen >> 8) & 0xff
		b2 := (dataLen >> 16) & 0xff
		b3 := (dataLen >> 24) & 0xff
		return "4e" + fmt.Sprintf("%02x%02x%02x%02x", b0, b1, b2, b3) + dataHex
	}
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

func decodeStateValue(hex string, offset int, fieldType string) (interface{}, int) {
	switch fieldType {
	case "bool":
		// 1 raw byte: 0x00 = false, 0x01 = true
		if offset+2 > len(hex) {
			return false, 2
		}
		return hex[offset:offset+2] != "00", 2
	case "int", "bigint":
		// 8 raw bytes LE sign-magnitude (NUM2BIN 8)
		byteWidth := 8
		hexWidth := byteWidth * 2
		if offset+hexWidth > len(hex) {
			return int64(0), hexWidth
		}
		return decodeNum2Bin(hex[offset : offset+hexWidth]), hexWidth
	case "PubKey":
		return hex[offset : offset+66], 66 // 33 bytes
	case "Addr", "Ripemd160":
		return hex[offset : offset+40], 40 // 20 bytes
	case "Sha256":
		return hex[offset : offset+64], 64 // 32 bytes
	case "Point", "P256Point":
		return hex[offset : offset+128], 128 // 64 bytes
	case "P384Point":
		return hex[offset : offset+192], 192 // 96 bytes
	default:
		// For unknown types, fall back to push-data decoding
		data, bytesRead := DecodePushData(hex, offset)
		return data, bytesRead
	}
}

// decodeNum2Bin decodes a fixed-width LE sign-magnitude number.
func decodeNum2Bin(hex string) int64 {
	bytes := hexToBytes(hex)
	if len(bytes) == 0 {
		return 0
	}
	negative := (bytes[len(bytes)-1] & 0x80) != 0
	bytes[len(bytes)-1] &= 0x7f

	var result int64
	for i := len(bytes) - 1; i >= 0; i-- {
		result = (result << 8) | int64(bytes[i])
	}

	if negative {
		return -result
	}
	return result
}

// DecodePushData decodes a state-section field at the given hex offset.
// Returns the field data (hex) and the total number of hex chars consumed.
//
// Exact inverse of encodePushDataState, and deliberately as strict as the
// compiler's on-chain state reader: only <len><data> framing is understood.
// OP_1..OP_16 (0x51..0x60) and OP_1NEGATE (0x4f) are NOT decoded as
// single-byte values — accepting them would let the SDK read a state section
// the contract's own script cannot parse. OP_0 (0x00) falls through to the
// opcode<=75 branch below and correctly decodes as the empty byte array.
func DecodePushData(hex string, offset int) (string, int) {
	if offset >= len(hex) {
		return "", 0
	}

	opcode, _ := strconv.ParseUint(hex[offset:offset+2], 16, 8)

	if opcode <= 75 {
		dataLen := int(opcode) * 2
		return hex[offset+2 : offset+2+dataLen], 2 + dataLen
	} else if opcode == 0x4c {
		// OP_PUSHDATA1
		length, _ := strconv.ParseUint(hex[offset+2:offset+4], 16, 8)
		dataLen := int(length) * 2
		return hex[offset+4 : offset+4+dataLen], 4 + dataLen
	} else if opcode == 0x4d {
		// OP_PUSHDATA2
		lo, _ := strconv.ParseUint(hex[offset+2:offset+4], 16, 8)
		hi, _ := strconv.ParseUint(hex[offset+4:offset+6], 16, 8)
		length := int(lo) | (int(hi) << 8)
		dataLen := length * 2
		return hex[offset+6 : offset+6+dataLen], 6 + dataLen
	} else if opcode == 0x4e {
		// OP_PUSHDATA4
		b0, _ := strconv.ParseUint(hex[offset+2:offset+4], 16, 8)
		b1, _ := strconv.ParseUint(hex[offset+4:offset+6], 16, 8)
		b2, _ := strconv.ParseUint(hex[offset+6:offset+8], 16, 8)
		b3, _ := strconv.ParseUint(hex[offset+8:offset+10], 16, 8)
		length := int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24)
		dataLen := length * 2
		return hex[offset+10 : offset+10+dataLen], 10 + dataLen
	}

	// Unknown opcode — treat as zero-length
	return "", 2
}

// DecodeScriptInt decodes a minimally-encoded Bitcoin Script integer from hex.
func DecodeScriptInt(hex string) int64 {
	if len(hex) == 0 || hex == "00" {
		return 0
	}

	bytes := hexToBytes(hex)
	negative := (bytes[len(bytes)-1] & 0x80) != 0
	bytes[len(bytes)-1] &= 0x7f

	var result int64
	for i := len(bytes) - 1; i >= 0; i-- {
		result = (result << 8) | int64(bytes[i])
	}

	if negative {
		return -result
	}
	return result
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

func bytesToHex(b []byte) string {
	var sb strings.Builder
	for _, v := range b {
		fmt.Fprintf(&sb, "%02x", v)
	}
	return sb.String()
}

func hexToBytes(hex string) []byte {
	bytes := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		bytes[i/2] = byte(v)
	}
	return bytes
}

// stateFieldInt64 coerces a bigint state value to int64 for OP_NUM2BIN
// encoding, PANICKING if its magnitude does not fit the fixed width-byte
// sign-magnitude state word.
//
// The check has to run HERE, not inside encodeNum2Bin: toInt64 destroys an
// oversized value before any encoder can see it — big.Int.Int64() sign-flips
// on overflow and strconv.ParseInt returns 0 on ErrRange — so by the time the
// bytes are written the wide value is already gone.
//
// width bytes of sign-magnitude hold 8*width-1 magnitude bits; the top bit of
// the last byte is the sign. encodeNum2Bin writes the low width bytes, drops
// everything above, then ORs the sign bit in on top of whatever landed there,
// so an oversized value used to serialise to a plausible but WRONG word:
//
//	2^63      -> 0000000000000080   reads back as 0   (negative zero)
//	2^63 + 5  -> 0500000000000080   reads back as -5  (sign flip)
//	2^64      -> 0000000000000000   reads back as 0
//
// The deploy then succeeded and the UTXO was unspendable: the covenant
// rebuilds the continuation with the compiler's own OP_NUM2BIN width, which
// cannot produce those bytes from that number, so hash256(outputs) never
// matches. ±(2^(8*width-1) - 1) stays representable and is unaffected.
//
// Panics rather than returning an error so SerializeState / GetLockingScript
// keep their signatures; this is the same "the value cannot be represented, so
// every result would be wrong" contract as checkedMul / checkedAdd in
// overflow.go.
func stateFieldInt64(value interface{}, label string, width int) int64 {
	limit := new(big.Int).Lsh(big.NewInt(1), uint(8*width-1))
	reject := func(n string) {
		panic(fmt.Sprintf(
			"runar: SerializeState: bigint state field %q = %s does not fit the fixed %d-byte "+
				"sign-magnitude state word (magnitude must be < 2^%d). Serializing it would write a "+
				"different number into the state section than the contract's on-chain OP_NUM2BIN %d "+
				"rebuilds, leaving the output unspendable",
			label, n, width, 8*width-1, width))
	}
	tooWide := func(n *big.Int) bool {
		return new(big.Int).Abs(n).Cmp(limit) >= 0
	}

	// Range-check the WIDE value first, while it is still intact.
	switch v := value.(type) {
	case *big.Int:
		if v != nil && tooWide(v) {
			reject(v.String())
		}
	case uint64:
		if n := new(big.Int).SetUint64(v); tooWide(n) {
			reject(n.String())
		}
	case float64:
		// JSON numbers decode to float64; 2^63 is exactly representable.
		if math.Abs(v) >= 9223372036854775808.0 {
			reject(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		s := strings.TrimSuffix(v, "n")
		if n, ok := new(big.Int).SetString(s, 10); ok && tooWide(n) {
			reject(n.String())
		}
	}

	n := toInt64(value)
	// -2^63 IS a valid int64, but its MAGNITUDE is 2^63 — one past the 63
	// magnitude bits — and it encoded as negative zero (0000000000000080).
	if tooWide(big.NewInt(n)) {
		reject(strconv.FormatInt(n, 10))
	}
	return n
}

func toInt64(value interface{}) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case float64:
		return int64(v)
	case uint64:
		return int64(v)
	case *big.Int:
		return v.Int64()
	case string:
		// Handle BigInt strings with "n" suffix from JSON (e.g. "0n", "1000n", "-42n")
		s := v
		if strings.HasSuffix(s, "n") {
			s = strings.TrimSuffix(s, "n")
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}
