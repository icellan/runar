package helpers

import (
	"fmt"
	"math/big"
	"strings"

	runar "github.com/icellan/runar/packages/runar-go"
)

// DecodeStateFromScript extracts state via the real Go SDK codec.
func DecodeStateFromScript(artifact *runar.RunarArtifact, scriptHex string) (map[string]interface{}, error) {
	st, err := runar.ExtractStateFromScript(artifact, scriptHex)
	if err != nil {
		return nil, fmt.Errorf("decoding state section of script (%d bytes): %w", len(scriptHex)/2, err)
	}
	if st == nil {
		return nil, fmt.Errorf("no OP_RETURN state section in script (%d bytes)", len(scriptHex)/2)
	}
	return st, nil
}

// AssertOnChainState fetches the call tx, decodes state at outputIndex, compares expected.
// expected values may be int64, string, or *big.Int.
func AssertOnChainState(
	artifact *runar.RunarArtifact,
	callTxid string,
	outputIndex int,
	expected map[string]interface{},
) (map[string]interface{}, error) {
	raw, err := GetRawTransaction(callTxid)
	if err != nil {
		return nil, err
	}
	hexStr, _ := raw["hex"].(string)
	if hexStr == "" {
		return nil, fmt.Errorf("getrawtransaction(%s): empty hex", callTxid)
	}
	// Prefer vout scripts from verbose RPC when available
	var scriptHex string
	if vout, ok := raw["vout"].([]interface{}); ok {
		if outputIndex >= len(vout) {
			return nil, fmt.Errorf("outputIndex %d out of range (vout len %d)", outputIndex, len(vout))
		}
		m, _ := vout[outputIndex].(map[string]interface{})
		spk, _ := m["scriptPubKey"].(map[string]interface{})
		scriptHex, _ = spk["hex"].(string)
	}
	if scriptHex == "" {
		// Fall back: parse raw hex outputs
		outs, perr := ParseOutputsFromRawTxHex(hexStr)
		if perr != nil {
			return nil, perr
		}
		if outputIndex >= len(outs) {
			return nil, fmt.Errorf("outputIndex %d out of range (outs %d)", outputIndex, len(outs))
		}
		scriptHex = outs[outputIndex].Script
	}
	decoded, err := DecodeStateFromScript(artifact, scriptHex)
	if err != nil {
		return nil, err
	}
	for k, want := range expected {
		got, ok := decoded[k]
		if !ok {
			return nil, fmt.Errorf("on-chain state missing field %q; got %#v", k, decoded)
		}
		if !stateValuesEqual(got, want) {
			return nil, fmt.Errorf("on-chain state.%s: got %#v, want %#v", k, got, want)
		}
	}
	return decoded, nil
}

// AssertByteString1BFraming checks state section starts with 0x01 <byte>, not OP_N.
func AssertByteString1BFraming(scriptHex string, expectedTagHex string) error {
	opRet := findLastOpReturnHex(scriptHex)
	if opRet < 0 {
		return fmt.Errorf("no OP_RETURN in locking script")
	}
	stateStart := opRet + 2
	if stateStart+4 > len(scriptHex) {
		return fmt.Errorf("state section too short")
	}
	framing := strings.ToLower(scriptHex[stateStart : stateStart+2])
	payload := strings.ToLower(scriptHex[stateStart+2 : stateStart+4])
	if framing != "01" {
		return fmt.Errorf("ByteString 1B framing: opcode 0x%s want 0x01 (not OP_N-as-length)", framing)
	}
	if payload != strings.ToLower(expectedTagHex) {
		return fmt.Errorf("ByteString 1B payload: got %s want %s", payload, expectedTagHex)
	}
	return nil
}

func findLastOpReturnHex(scriptHex string) int {
	// Align with SDK FindLastOpReturn: first OP_RETURN at an opcode boundary.
	// After OP_RETURN, remaining bytes are raw state data (not opcodes).
	i := 0
	for i+2 <= len(scriptHex) {
		op, err := parseHexByteLocal(scriptHex[i : i+2])
		if err != nil {
			return -1
		}
		if op == 0x6a {
			return i
		}
		if op > 0 && op <= 75 {
			i += 2 + int(op)*2
			continue
		}
		if op == 0x4c && i+4 <= len(scriptHex) {
			ln, _ := parseHexByteLocal(scriptHex[i+2 : i+4])
			i += 4 + int(ln)*2
			continue
		}
		if op == 0x4d && i+6 <= len(scriptHex) {
			lo, _ := parseHexByteLocal(scriptHex[i+2 : i+4])
			hi, _ := parseHexByteLocal(scriptHex[i+4 : i+6])
			ln := int(lo) | (int(hi) << 8)
			i += 6 + ln*2
			continue
		}
		if op == 0x4e && i+10 <= len(scriptHex) {
			// OP_PUSHDATA4
			b0, _ := parseHexByteLocal(scriptHex[i+2 : i+4])
			b1, _ := parseHexByteLocal(scriptHex[i+4 : i+6])
			b2, _ := parseHexByteLocal(scriptHex[i+6 : i+8])
			b3, _ := parseHexByteLocal(scriptHex[i+8 : i+10])
			ln := int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24)
			i += 10 + ln*2
			continue
		}
		i += 2
	}
	return -1
}

func parseHexByteLocal(s string) (uint64, error) {
	var val uint64
	for _, c := range s {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			val |= uint64(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("bad hex")
		}
	}
	return val, nil
}

// ParsedOut is a locking-script + satoshis pair from a raw tx.
type ParsedOut struct {
	Satoshis int64
	Script   string
}

// ParseOutputsFromRawTxHex re-exports the lightweight parser used by data_outputs tests.
// Defined here so residual helpers can share it without import cycles on test package.
func ParseOutputsFromRawTxHex(txHex string) ([]ParsedOut, error) {
	outs, err := parseOutputsHex(txHex)
	if err != nil {
		return nil, err
	}
	return outs, nil
}

func parseOutputsHex(hex string) ([]ParsedOut, error) {
	pos := 0
	pos += 8 // version
	nIn, w := readVarIntOnchain(hex, pos)
	pos += w
	for i := 0; i < nIn; i++ {
		pos += 64 + 8
		scriptLen, slw := readVarIntOnchain(hex, pos)
		pos += slw + scriptLen*2 + 8
	}
	nOut, w := readVarIntOnchain(hex, pos)
	pos += w
	outs := make([]ParsedOut, 0, nOut)
	for i := 0; i < nOut; i++ {
		sats := int64(0)
		for j := 0; j < 8; j++ {
			b, err := parseHexByteLocal(hex[pos : pos+2])
			if err != nil {
				return nil, err
			}
			sats |= int64(b) << (8 * j)
			pos += 2
		}
		scriptLen, slw := readVarIntOnchain(hex, pos)
		pos += slw
		script := hex[pos : pos+scriptLen*2]
		pos += scriptLen * 2
		outs = append(outs, ParsedOut{Satoshis: sats, Script: script})
	}
	return outs, nil
}

func readVarIntOnchain(hex string, pos int) (int, int) {
	first, _ := parseHexByteLocal(hex[pos : pos+2])
	if first < 0xfd {
		return int(first), 2
	}
	if first == 0xfd {
		lo, _ := parseHexByteLocal(hex[pos+2 : pos+4])
		hi, _ := parseHexByteLocal(hex[pos+4 : pos+6])
		return int(lo) | (int(hi) << 8), 6
	}
	return 0, 2
}

func stateValuesEqual(got, want interface{}) bool {
	switch w := want.(type) {
	case int64:
		return asInt64(got) == w
	case int:
		return asInt64(got) == int64(w)
	case string:
		gs, ok := got.(string)
		return ok && strings.EqualFold(gs, w)
	case *big.Int:
		return asBigInt(got).Cmp(w) == 0
	default:
		return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want)
	}
}

func asInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	case *big.Int:
		return n.Int64()
	case big.Int:
		return n.Int64()
	default:
		return 0
	}
}

func asBigInt(v interface{}) *big.Int {
	switch n := v.(type) {
	case *big.Int:
		return n
	case big.Int:
		return new(big.Int).Set(&n)
	case int64:
		return big.NewInt(n)
	case int:
		return big.NewInt(int64(n))
	default:
		return big.NewInt(0)
	}
}
