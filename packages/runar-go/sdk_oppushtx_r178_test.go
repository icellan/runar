package runar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-178 (CL-BUG-071): an out-of-range codeSeparatorIndex used to PANIC here —
// `subscript[(codeSeparatorIndex+1)*2:]` with "slice bounds out of range" — so
// a fund-moving primitive took down the caller's process instead of reporting
// a bad input. (Peer tiers got it wrong differently: rust/python/ruby/zig
// signed the UNTRIMMED subscript, ts signed an EMPTY one.)
func r178Scenario(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "conformance", "sdk-bip143", "fixtures.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var doc struct {
		Scenarios []map[string]any `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	if len(doc.Scenarios) == 0 {
		t.Fatal("fixture has no scenarios")
	}
	return doc.Scenarios[0]
}

func TestR178_OutOfRangeCodeSeparatorIndexIsRefused(t *testing.T) {
	s := r178Scenario(t)
	txHex := s["unsignedTxHex"].(string)
	subscript := s["prevScriptHex"].(string)
	inputIndex := int(s["inputIndex"].(float64))
	sats := int64(s["prevValueSats"].(float64))

	pastTheEnd := len(subscript) / 2
	for _, idx := range []int{pastTheEnd, pastTheEnd + 1, pastTheEnd + 99} {
		_, _, err := ComputeOpPushTxWithCodeSep(txHex, inputIndex, subscript, sats, idx)
		if err == nil {
			t.Fatalf("codeSeparatorIndex %d past the end was accepted", idx)
		}
		if !strings.Contains(err.Error(), "codeSeparatorIndex") {
			t.Errorf("the refusal must name the offending input; got: %v", err)
		}
	}
}

// N-155: codeSeparatorIndex pointing at the LAST byte of the subscript passes
// the R-178 "past the end" check (trimPos == len, not >) but trims scriptCode
// down to the empty string -- the same unsignable condition as an empty
// subscript, reached via the separator offset instead. Proves: ComputeOpPushTx
// refuses this case. Does not prove anything about ExternalSigner.Sign (it
// already rejects any empty string it is handed) or about callers upstream
// that compute the codeSeparatorIndex they pass in.
func TestN155_CodeSeparatorOnLastByteIsRefused(t *testing.T) {
	txHex := "01000000" +
		"01" +
		strings.Repeat("11", 32) +
		"00000000" +
		"00" +
		"ffffffff" +
		"01" +
		"e803000000000000" +
		"0151" +
		"00000000"

	oneByte := "51" // OP_1 -- codeSeparatorIndex 0 is its last (and only) byte
	_, _, err := ComputeOpPushTxWithCodeSep(txHex, 0, oneByte, 1000, 0)
	if err == nil {
		t.Fatal("codeSeparatorIndex on the subscript's last byte was accepted")
	}
	if !strings.Contains(err.Error(), "empty subscript") {
		t.Errorf("the refusal must name the empty-subscript condition; got: %v", err)
	}
}

func TestR178_InRangeCodeSeparatorIndexStillTrims(t *testing.T) {
	s := r178Scenario(t)
	txHex := s["unsignedTxHex"].(string)
	subscript := s["prevScriptHex"].(string)
	inputIndex := int(s["inputIndex"].(float64))
	sats := int64(s["prevValueSats"].(float64))

	_, trimmed, err := ComputeOpPushTxWithCodeSep(txHex, inputIndex, subscript, sats, 0)
	if err != nil {
		t.Fatalf("an in-range separator must still work: %v", err)
	}
	_, untrimmed, err := ComputeOpPushTx(txHex, inputIndex, subscript, sats)
	if err != nil {
		t.Fatalf("no separator must still work: %v", err)
	}
	if string(trimmed) == string(untrimmed) {
		t.Error("trimming the subscript must change the preimage")
	}
}
