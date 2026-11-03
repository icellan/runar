package ir

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// N-069: LoadIRFromBytes checks every required ANF field for presence and JSON
// type and names the field path, with the diagnostic shared verbatim by all
// seven tiers (conformance/negatives/ir-required-fields-cases.json).
//
// Before: an omitted method `body` was refused only by the unrelated
// terminal-assert rule, and a wrongly typed field by encoding/json's raw
// "cannot unmarshal ... into Go struct field" message.
//
// Proves: each single-field corruption of the control is refused with its
// exact diagnostic and the control loads. Does not prove: full schema
// conformance (deliberately defaulted optional fields are not required).
func TestN069_RequiredFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", "ir-required-fields-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Control json.RawMessage `json:"control"`
		Cases   []struct {
			Name  string          `json:"name"`
			IR    json.RawMessage `json:"ir"`
			Error string          `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIRFromBytes(corpus.Control); err != nil {
		t.Fatalf("control refused: %v", err)
	}
	if len(corpus.Cases) < 20 {
		t.Fatalf("corpus has only %d cases", len(corpus.Cases))
	}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			_, err := LoadIRFromBytes(c.IR)
			if err == nil {
				t.Fatalf("accepted; want %q", c.Error)
			}
			if err.Error() != c.Error {
				t.Fatalf("got  %q\nwant %q", err.Error(), c.Error)
			}
		})
	}
}
