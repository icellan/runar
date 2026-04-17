package runar

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 1sat ordinals — inscription envelope build/parse and BSV-20/BSV-21 helpers
// ---------------------------------------------------------------------------
//
// Envelope layout:
//   OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(<content-type>) OP_0 PUSH(<data>) OP_ENDIF
//
// Hex:
//   00 63 03 6f7264 51 <push content-type> 00 <push data> 68
//
// The envelope is a no-op (OP_FALSE causes the IF block to be skipped)
// and can be placed anywhere in a script without affecting execution.
// ---------------------------------------------------------------------------

// Inscription represents a 1sat ordinals inscription with its content type
// and hex-encoded payload.
type Inscription struct {
	ContentType string `json:"contentType"`
	Data        string `json:"data"` // hex-encoded content
}

// EnvelopeBounds represents the hex-char offsets bounding an inscription
// envelope within a script.
type EnvelopeBounds struct {
	StartHex int `json:"startHex"` // hex-char offset where the envelope starts (at OP_FALSE)
	EndHex   int `json:"endHex"`   // hex-char offset where the envelope ends (after OP_ENDIF)
}

// ---------------------------------------------------------------------------
// UTF-8 / hex helpers
// ---------------------------------------------------------------------------

// utf8ToHex converts a UTF-8 string to its hex representation.
func utf8ToHex(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&sb, "%02x", s[i])
	}
	return sb.String()
}

// hexToUtf8 converts a hex string to a UTF-8 string.
func hexToUtf8(h string) string {
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		v, _ := strconv.ParseUint(h[i:i+2], 16, 8)
		b[i/2] = byte(v)
	}
	return string(b)
}

// encodePushDataOrd encodes push data for inscription envelopes. This is
// identical in semantics to EncodePushData in sdk_state.go but kept as a
// separate unexported helper to mirror the TypeScript envelope module's
// local encodePushData.
func encodePushDataOrd(dataHex string) string {
	if len(dataHex) == 0 {
		return "00" // OP_0
	}
	return EncodePushData(dataHex)
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// BuildInscriptionEnvelope builds a 1sat ordinals inscription envelope as hex.
//
// contentType is the MIME type (e.g. "image/png", "application/bsv-20").
// data is the hex-encoded inscription content.
// Returns the hex string of the full envelope script fragment.
func BuildInscriptionEnvelope(contentType, data string) string {
	contentTypeHex := utf8ToHex(contentType)

	// OP_FALSE (00) OP_IF (63) PUSH "ord" (03 6f7264) OP_1 (51)
	hex := "006303" + "6f7264" + "51"
	// PUSH content-type
	hex += encodePushDataOrd(contentTypeHex)
	// OP_0 (00) -- content delimiter
	hex += "00"
	// PUSH data
	hex += encodePushDataOrd(data)
	// OP_ENDIF (68)
	hex += "68"

	return hex
}

// ---------------------------------------------------------------------------
// Parse / Find
// ---------------------------------------------------------------------------

// readPushData reads a push-data value at the given hex offset. Returns the
// pushed data (hex) and the total number of hex chars consumed (including the
// length prefix). Returns ("", 0, false) if the data is invalid.
func readPushData(scriptHex string, offset int) (data string, bytesRead int, ok bool) {
	if offset+2 > len(scriptHex) {
		return "", 0, false
	}
	opcode, _ := strconv.ParseUint(scriptHex[offset:offset+2], 16, 8)

	if opcode >= 0x01 && opcode <= 0x4b {
		dataLen := int(opcode) * 2
		if offset+2+dataLen > len(scriptHex) {
			return "", 0, false
		}
		return scriptHex[offset+2 : offset+2+dataLen], 2 + dataLen, true
	} else if opcode == 0x4c {
		// OP_PUSHDATA1
		if offset+4 > len(scriptHex) {
			return "", 0, false
		}
		length, _ := strconv.ParseUint(scriptHex[offset+2:offset+4], 16, 8)
		dataLen := int(length) * 2
		if offset+4+dataLen > len(scriptHex) {
			return "", 0, false
		}
		return scriptHex[offset+4 : offset+4+dataLen], 4 + dataLen, true
	} else if opcode == 0x4d {
		// OP_PUSHDATA2
		if offset+6 > len(scriptHex) {
			return "", 0, false
		}
		lo, _ := strconv.ParseUint(scriptHex[offset+2:offset+4], 16, 8)
		hi, _ := strconv.ParseUint(scriptHex[offset+4:offset+6], 16, 8)
		length := int(lo) | (int(hi) << 8)
		dataLen := length * 2
		if offset+6+dataLen > len(scriptHex) {
			return "", 0, false
		}
		return scriptHex[offset+6 : offset+6+dataLen], 6 + dataLen, true
	} else if opcode == 0x4e {
		// OP_PUSHDATA4
		if offset+10 > len(scriptHex) {
			return "", 0, false
		}
		b0, _ := strconv.ParseUint(scriptHex[offset+2:offset+4], 16, 8)
		b1, _ := strconv.ParseUint(scriptHex[offset+4:offset+6], 16, 8)
		b2, _ := strconv.ParseUint(scriptHex[offset+6:offset+8], 16, 8)
		b3, _ := strconv.ParseUint(scriptHex[offset+8:offset+10], 16, 8)
		length := int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24)
		dataLen := length * 2
		if offset+10+dataLen > len(scriptHex) {
			return "", 0, false
		}
		return scriptHex[offset+10 : offset+10+dataLen], 10 + dataLen, true
	}

	return "", 0, false
}

// opcodeSize computes the number of hex chars an opcode occupies (including its
// push data) so we can advance past it while walking a script.
func opcodeSize(scriptHex string, offset int) int {
	if offset+2 > len(scriptHex) {
		return 2
	}
	opcode, _ := strconv.ParseUint(scriptHex[offset:offset+2], 16, 8)

	if opcode >= 0x01 && opcode <= 0x4b {
		return 2 + int(opcode)*2
	} else if opcode == 0x4c {
		if offset+4 > len(scriptHex) {
			return 2
		}
		length, _ := strconv.ParseUint(scriptHex[offset+2:offset+4], 16, 8)
		return 4 + int(length)*2
	} else if opcode == 0x4d {
		if offset+6 > len(scriptHex) {
			return 2
		}
		lo, _ := strconv.ParseUint(scriptHex[offset+2:offset+4], 16, 8)
		hi, _ := strconv.ParseUint(scriptHex[offset+4:offset+6], 16, 8)
		return 6 + (int(lo)|(int(hi)<<8))*2
	} else if opcode == 0x4e {
		if offset+10 > len(scriptHex) {
			return 2
		}
		b0, _ := strconv.ParseUint(scriptHex[offset+2:offset+4], 16, 8)
		b1, _ := strconv.ParseUint(scriptHex[offset+4:offset+6], 16, 8)
		b2, _ := strconv.ParseUint(scriptHex[offset+6:offset+8], 16, 8)
		b3, _ := strconv.ParseUint(scriptHex[offset+8:offset+10], 16, 8)
		return 10 + (int(b0)|(int(b1)<<8)|(int(b2)<<16)|(int(b3)<<24))*2
	}

	return 2 // all other opcodes are 1 byte
}

// FindInscriptionEnvelope finds the inscription envelope within a script hex
// string. Walks the script as Bitcoin Script opcodes looking for the pattern:
//
//	OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) ...
//
// Returns hex-char offsets of the envelope, or nil if not found.
func FindInscriptionEnvelope(scriptHex string) *EnvelopeBounds {
	offset := 0
	length := len(scriptHex)

	for offset+2 <= length {
		opcode, _ := strconv.ParseUint(scriptHex[offset:offset+2], 16, 8)

		// Look for OP_FALSE (0x00)
		if opcode == 0x00 {
			// Check: OP_IF (63) PUSH3 (03) "ord" (6f7264)
			if offset+12 <= length &&
				scriptHex[offset+2:offset+4] == "63" &&
				scriptHex[offset+4:offset+12] == "036f7264" {

				envelopeStart := offset
				// Skip: OP_FALSE(2) + OP_IF(2) + PUSH3 "ord"(8) = 12 hex chars
				pos := offset + 12

				// Expect OP_1 (0x51)
				if pos+2 > length || scriptHex[pos:pos+2] != "51" {
					offset += 2
					continue
				}
				pos += 2 // skip OP_1

				// Read content-type push
				_, ctRead, ctOk := readPushData(scriptHex, pos)
				if !ctOk {
					offset += 2
					continue
				}
				pos += ctRead

				// Expect OP_0 (0x00) -- content delimiter
				if pos+2 > length || scriptHex[pos:pos+2] != "00" {
					offset += 2
					continue
				}
				pos += 2 // skip OP_0

				// Read data push
				_, dataRead, dataOk := readPushData(scriptHex, pos)
				if !dataOk {
					offset += 2
					continue
				}
				pos += dataRead

				// Expect OP_ENDIF (0x68)
				if pos+2 > length || scriptHex[pos:pos+2] != "68" {
					offset += 2
					continue
				}
				pos += 2 // skip OP_ENDIF

				return &EnvelopeBounds{StartHex: envelopeStart, EndHex: pos}
			}
		}

		// Advance past this opcode
		offset += opcodeSize(scriptHex, offset)
	}

	return nil
}

// ParseInscriptionEnvelope parses an inscription envelope from a script hex
// string. Returns the inscription data, or nil if no envelope is found.
func ParseInscriptionEnvelope(scriptHex string) *Inscription {
	bounds := FindInscriptionEnvelope(scriptHex)
	if bounds == nil {
		return nil
	}

	envelopeHex := scriptHex[bounds.StartHex:bounds.EndHex]

	// Parse the envelope contents:
	// 00 63 03 6f7264 51 <ct-push> 00 <data-push> 68
	pos := 12 // skip OP_FALSE + OP_IF + PUSH3 "ord"
	pos += 2  // skip OP_1

	ctData, ctRead, ctOk := readPushData(envelopeHex, pos)
	if !ctOk {
		return nil
	}
	pos += ctRead

	pos += 2 // skip OP_0

	dataData, _, dataOk := readPushData(envelopeHex, pos)
	if !dataOk {
		return nil
	}

	return &Inscription{
		ContentType: hexToUtf8(ctData),
		Data:        dataData,
	}
}

// StripInscriptionEnvelope removes the inscription envelope from a script,
// returning the bare script. Returns the original if no envelope is found.
func StripInscriptionEnvelope(scriptHex string) string {
	bounds := FindInscriptionEnvelope(scriptHex)
	if bounds == nil {
		return scriptHex
	}
	return scriptHex[:bounds.StartHex] + scriptHex[bounds.EndHex:]
}

// ---------------------------------------------------------------------------
// BSV-20 (v1) -- tick-based fungible tokens
// ---------------------------------------------------------------------------

// BSV20Deploy builds a BSV-20 deploy inscription.
// lim and dec are optional (pass nil to omit).
func BSV20Deploy(tick, max string, lim, dec *string) *Inscription {
	pairs := []kvPair{
		{"p", "bsv-20"},
		{"op", "deploy"},
		{"tick", tick},
		{"max", max},
	}
	if lim != nil {
		pairs = append(pairs, kvPair{"lim", *lim})
	}
	if dec != nil {
		pairs = append(pairs, kvPair{"dec", *dec})
	}
	return orderedJSONInscription(pairs)
}

// BSV20Mint builds a BSV-20 mint inscription.
func BSV20Mint(tick, amt string) *Inscription {
	return orderedJSONInscription([]kvPair{
		{"p", "bsv-20"},
		{"op", "mint"},
		{"tick", tick},
		{"amt", amt},
	})
}

// BSV20Transfer builds a BSV-20 transfer inscription.
func BSV20Transfer(tick, amt string) *Inscription {
	return orderedJSONInscription([]kvPair{
		{"p", "bsv-20"},
		{"op", "transfer"},
		{"tick", tick},
		{"amt", amt},
	})
}

// ---------------------------------------------------------------------------
// BSV-21 (v2) -- ID-based fungible tokens
// ---------------------------------------------------------------------------

// BSV21DeployMint builds a BSV-21 deploy+mint inscription.
// dec, sym, and icon are optional (pass nil to omit).
func BSV21DeployMint(amt string, dec, sym, icon *string) *Inscription {
	pairs := []kvPair{
		{"p", "bsv-20"},
		{"op", "deploy+mint"},
		{"amt", amt},
	}
	if dec != nil {
		pairs = append(pairs, kvPair{"dec", *dec})
	}
	if sym != nil {
		pairs = append(pairs, kvPair{"sym", *sym})
	}
	if icon != nil {
		pairs = append(pairs, kvPair{"icon", *icon})
	}
	return orderedJSONInscription(pairs)
}

// BSV21Transfer builds a BSV-21 transfer inscription.
func BSV21Transfer(id, amt string) *Inscription {
	return orderedJSONInscription([]kvPair{
		{"p", "bsv-20"},
		{"op", "transfer"},
		{"id", id},
		{"amt", amt},
	})
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// kvPair is a key-value pair for building ordered JSON.
type kvPair struct {
	Key   string
	Value string
}

// orderedJSONInscription creates an inscription with content type
// "application/bsv-20" and the given key-value pairs serialized as JSON hex.
// Keys are written in the provided order, matching the TypeScript
// JSON.stringify insertion-order behaviour.
func orderedJSONInscription(pairs []kvPair) *Inscription {
	var parts []string
	for _, kv := range pairs {
		k, _ := json.Marshal(kv.Key)
		v, _ := json.Marshal(kv.Value)
		parts = append(parts, string(k)+":"+string(v))
	}
	jsonStr := "{" + strings.Join(parts, ",") + "}"
	return &Inscription{
		ContentType: "application/bsv-20",
		Data:        utf8ToHex(jsonStr),
	}
}
