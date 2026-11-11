package runar

// MatchesArtifact must check what sits at each constructor slot, not only the
// template bytes between slots: a push or small-integer opcode, the same bytes
// at every reference of one param, and exactly fixedValueByteLength bytes where
// the slot declares it. A stateful artifact's script must carry an OP_RETURN
// after its code part.
//
// Replays the shared cross-tier vector
// conformance/sdk-matches-artifact/slot-values.json (also replayed by the TS,
// Rust, Python, Zig, Ruby and Java SDKs), plus the TS unit cases for hex case,
// ExtractConstructorArgs refusing a non-push opcode, and ExtractConstructorArgs
// after a codeSepIndex slot wider than one byte.
//
// PROVES: honest deployments match; the forgeries in the vector do not;
// ExtractConstructorArgs returns *MalformedScriptError on a non-push opcode at
// any reference of a param and reads an arg after a wide codeSep slot from its
// deployed position.
// DOES NOT PROVE: that a slot push is minimally encoded, nor anything about the
// length of the state after the OP_RETURN.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const slotValuesG = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

type slotValuesFixture struct {
	Artifacts map[string]RunarArtifact `json:"artifacts"`
	Cases     []struct {
		Name      string `json:"name"`
		Artifact  string `json:"artifact"`
		ScriptHex string `json:"script_hex"`
		Expected  bool   `json:"expected"`
	} `json:"cases"`
}

func loadSlotValuesFixture(t *testing.T) slotValuesFixture {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-matches-artifact", "slot-values.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx slotValuesFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	return fx
}

func TestSlotValues_MatchesArtifactVector(t *testing.T) {
	fx := loadSlotValuesFixture(t)
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

func TestSlotValues_HexCaseIgnored(t *testing.T) {
	fx := loadSlotValuesFixture(t)
	owner2 := fx.Artifacts["owner2"]
	got, err := MatchesArtifact(&owner2, "21"+slotValuesG+"ad21"+strings.ToUpper(slotValuesG)+"ac")
	if err != nil || !got {
		t.Fatalf("MatchesArtifact = %v, %v; want true", got, err)
	}
}

func TestSlotValues_ExtractRefusesNonPush(t *testing.T) {
	fx := loadSlotValuesFixture(t)
	owner2 := fx.Artifacts["owner2"]
	slotMatrix := fx.Artifacts["slotMatrix"]
	cases := []struct {
		name   string
		art    *RunarArtifact
		script string
	}{
		{"first reference", &owner2, "acad21" + slotValuesG + "ac"},
		{"later reference", &owner2, "21" + slotValuesG + "adacac"},
		{"SlotMatrix", &slotMatrix, "ac7b880111" + "7c9dac" + "21" + slotValuesG + "879169" + "21" + slotValuesG + "ac"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := ExtractConstructorArgs(c.art, c.script)
			var mse *MalformedScriptError
			if !errors.As(err, &mse) {
				t.Fatalf("ExtractConstructorArgs err = %v, want *MalformedScriptError", err)
			}
		})
	}
}

func TestSlotValues_ExtractHonest(t *testing.T) {
	fx := loadSlotValuesFixture(t)
	slotMatrix := fx.Artifacts["slotMatrix"]
	owner2 := fx.Artifacts["owner2"]
	for _, c := range fx.Cases {
		if c.Expected && c.Artifact == "slotMatrix" {
			args, err := ExtractConstructorArgs(&slotMatrix, c.ScriptHex)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if args["owner"] != slotValuesG {
				t.Fatalf("%s: owner = %v", c.Name, args["owner"])
			}
			if n, ok := args["count"].(int64); !ok || n != 17 {
				t.Fatalf("%s: count = %#v, want 17", c.Name, args["count"])
			}
		}
		if c.Name == "owner2-honest" {
			args, err := ExtractConstructorArgs(&owner2, c.ScriptHex)
			if err != nil || len(args) != 1 || args["owner"] != slotValuesG {
				t.Fatalf("owner2-honest: %v, %v", args, err)
			}
		}
	}
}

func TestSlotValues_ExtractAfterWideCodeSepSlot(t *testing.T) {
	// Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked as
	// 143 (`02 8f00`), then a constructor slot at byte 3. Script pinned by the
	// TS SDK's RunarContract.getLockingScript().
	art := &RunarArtifact{
		Version:           "runar-v1.0.0-rc.1",
		CompilerVersion:   "1.0.0-rc.1",
		ContractName:      "CodeSepBeforeSlot",
		ABI:               ABI{Constructor: ABIConstructor{Params: []ABIParam{{Name: "x", Type: "ByteString"}}}},
		Script:            "5100520053",
		ConstructorSlots:  []ConstructorSlot{{ParamIndex: 0, ByteOffset: 3}},
		CodeSepIndexSlots: []CodeSepIndexSlot{{ByteOffset: 1, CodeSepIndex: 140}},
	}
	script := "51028f005203aabbcc53"
	ok, err := MatchesArtifact(art, script)
	if err != nil || !ok {
		t.Fatalf("MatchesArtifact = %v, %v; want true", ok, err)
	}
	args, err := ExtractConstructorArgs(art, script)
	if err != nil {
		t.Fatalf("ExtractConstructorArgs: %v", err)
	}
	if len(args) != 1 || args["x"] != "aabbcc" {
		t.Fatalf("ExtractConstructorArgs = %v, want {x: aabbcc}", args)
	}
}
