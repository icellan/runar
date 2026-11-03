package runar

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// N-246: ExtractOutputHash must return the preimage's actual hashOutputs
// field, not the leading 32 bytes (which cover nVersion + most of
// hashPrevouts in a real BIP-143 preimage). Mirrors the landed TS fix
// (N-245, packages/runar-lang/src/runtime/preimage.ts) and the Java fix
// (N-188, Preimage.extractOutputHash).
//
// buildPreimageHexN246 lays out a syntactically valid BIP-143 preimage with
// a zero-length scriptCode, so every field lands at its fixed offset:
//
//	version(4) hashPrevouts(32) hashSequence(32) outpoint(36)
//	scriptCodeLen(1=0x00) amount(8) sequence(4) hashOutputs(32)
//	locktime(4) sighashType(4)
func buildPreimageHexN246(hashPrevoutsByte, hashOutputsByte string) string {
	version := "01000000"
	hashPrevouts := strings.Repeat(hashPrevoutsByte, 32)
	hashSequence := strings.Repeat("00", 32)
	outpoint := strings.Repeat("00", 36)
	scriptCodeLen := "00"
	amount := "1027000000000000" // 10000 satoshis, LE int64
	sequence := "feffffff"
	hashOutputs := strings.Repeat(hashOutputsByte, 32)
	locktime := "00000000"
	sighashType := "41000000"
	return version + hashPrevouts + hashSequence + outpoint + scriptCodeLen +
		amount + sequence + hashOutputs + locktime + sighashType
}

// TestExtractOutputHash_ReturnsHashOutputs_N246 proves ExtractOutputHash
// reads the end-relative hashOutputs window (bytes[len-40:len-8]), matching
// the compiled opcode sequence (OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32
// OP_SPLIT OP_DROP), instead of echoing bytes[0:32] (nVersion + most of
// hashPrevouts). It does not prove anything about on-chain behaviour, which
// this mock never touches.
func TestExtractOutputHash_ReturnsHashOutputs_N246(t *testing.T) {
	raw, err := hex.DecodeString(buildPreimageHexN246("aa", "bb"))
	if err != nil {
		t.Fatalf("failed to decode test preimage: %v", err)
	}
	preimage := SigHashPreimage(raw)
	result := ExtractOutputHash(preimage)

	wantBB := bytes.Repeat([]byte{0xbb}, 32)
	wantAA := bytes.Repeat([]byte{0xaa}, 32)
	if !bytes.Equal([]byte(result), wantBB) {
		t.Fatalf("ExtractOutputHash = %x, want hashOutputs = %x", []byte(result), wantBB)
	}
	if bytes.Equal([]byte(result), wantAA) {
		t.Fatal("ExtractOutputHash echoed the leading bytes (version + hashPrevouts) instead of hashOutputs")
	}
}
