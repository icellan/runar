package runar

// N-316: MatchesArtifact must treat CodeSepIndexSlots and CodePartLenSlots as
// variable script elements even when ConstructorSlots is empty.
//
// Replays the shared cross-tier fixture
// conformance/sdk-matches-artifact/fixtures.json (also replayed by the TS,
// Rust, Python, Zig, Ruby and Java SDKs). Its first artifact is real compiler
// output for a stateful contract with no constructor args.
//
// PROVES: an honest deployment of such an artifact matches it, and a script
// differing in one code byte before/after the slot does not.
// DOES NOT PROVE: on-chain spendability, or slot layouts beyond the fixture.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestN316_MatchesArtifactSlotOnlyArtifacts(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-matches-artifact", "fixtures.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		Cases []struct {
			Name      string        `json:"name"`
			Artifact  RunarArtifact `json:"artifact"`
			ScriptHex string        `json:"script_hex"`
			Expected  bool          `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	for _, c := range fx.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			got, err := MatchesArtifact(&c.Artifact, c.ScriptHex)
			if err != nil {
				t.Fatalf("MatchesArtifact: %v", err)
			}
			if got != c.Expected {
				t.Fatalf("MatchesArtifact = %v, want %v", got, c.Expected)
			}
		})
	}
}
