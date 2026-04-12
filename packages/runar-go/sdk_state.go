package runar

import (
	"fmt"
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
				hex.WriteString(encodeStateValue(elem, leafType))
			}
		} else {
			value := values[field.Name]
			hex.WriteString(encodeStateValue(value, field.Type))
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
func encodeStateValue(value interface{}, fieldType string) string {
	switch fieldType {
	case "int", "bigint":
		n := toInt64(value)
		return encodeNum2Bin(n, 8)
	case "bool":
		b, _ := value.(bool)
		if b {
			return "01"
		}
		return "00"
	case "PubKey", "Addr", "Ripemd160", "Sha256", "Point":
		// Fixed-size byte types: raw hex, no framing needed.
		return fmt.Sprintf("%v", value)
	default:
		// Variable-length types (bytes, ByteString, etc.): use push-data
		// encoding so the decoder can determine the length.
		hex := fmt.Sprintf("%v", value)
		if len(hex) == 0 {
			return "00" // OP_0
		}
		return EncodePushData(hex)
	}
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
func EncodePushData(dataHex string) string {
	dataLen := len(dataHex) / 2

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
	case "Point":
		return hex[offset : offset+128], 128 // 64 bytes
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

// DecodePushData decodes a Bitcoin Script push data at the given hex offset.
// Returns the pushed data (hex) and the total number of hex chars consumed.
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
