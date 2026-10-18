package runar

// N-318: MatchesArtifact must check the VALUE at every codeSepIndex slot.
// Deploy bakes encodeScriptNumber(codeSepIndex + shift) there (shift = growth
// of every constructor slot, and every earlier codeSep slot, before
// codeSepIndex); the matcher used to accept any element at the slot.
//
// Replays the shared cross-tier vector
// conformance/sdk-matches-artifact/codesep.json (also replayed by the TS,
// Rust, Python, Zig, Ruby and Java SDKs): honest TS-SDK deployments of a real
// compiled artifact and of a synthetic artifact whose baked values depend on a
// variable-length constructor arg, plus forgeries differing only in the
// number pushed at a codeSep slot.
//
// PROVES: honest deployments match whatever the constructor-arg width, and a
// forged separator index (OP_0, off by one, non-minimal, unshifted) does not.
// DOES NOT PROVE: on-chain spendability of the honest scripts.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestN318_MatchesArtifactChecksCodeSepValue(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-matches-artifact", "codesep.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		Artifacts map[string]RunarArtifact `json:"artifacts"`
		Cases     []struct {
			Name      string `json:"name"`
			Artifact  string `json:"artifact"`
			ScriptHex string `json:"script_hex"`
			Expected  bool   `json:"expected"`
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
			art, ok := fx.Artifacts[c.Artifact]
			if !ok {
				t.Fatalf("unknown artifact %q", c.Artifact)
			}
			got, err := MatchesArtifact(&art, c.ScriptHex)
			if err != nil {
				t.Fatalf("MatchesArtifact: %v", err)
			}
			if got != c.Expected {
				t.Fatalf("MatchesArtifact = %v, want %v", got, c.Expected)
			}
		})
	}
}
