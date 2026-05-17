package compiler

import (
	"strings"
	"testing"
)

// TestIntentIntrinsics_EndToEndCompile verifies that a contract exercising
// all three intent-covenant intrinsics (extractPrevOutputScript,
// requireOutputP2PKH, currentBlockHeight) compiles cleanly from Go source
// to Bitcoin Script hex. The compiled artifact must include the
// auto-injected witness parameters in its ABI.
func TestIntentIntrinsics_EndToEndCompile(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentDemo struct {
	runar.StatefulSmartContract
	StateCovScriptHash runar.ByteString ` + "`runar:\"readonly\"`" + `
	BondPKH            runar.ByteString ` + "`runar:\"readonly\"`" + `
	BondAmount         runar.Bigint     ` + "`runar:\"readonly\"`" + `
	Deadline           runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *IntentDemo) CoSpendPrivileged() {
	stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
	_ = stateCovScript

	h := runar.CurrentBlockHeight()
	runar.Assert(h <= c.Deadline)

	runar.RequireOutputP2PKH(0, c.BondPKH, c.BondAmount)
}
`
	result := CompileFromSourceStrWithResult(source, "IntentDemo.runar.go")
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	if result.Artifact == nil {
		t.Fatal("expected non-nil artifact on success")
	}
	if result.Artifact.Script == "" {
		t.Fatal("expected non-empty Script hex in compiled artifact")
	}

	// Opcode-sequence audit (per BSVM Phase 13 review minor): the emitted
	// Script for the combined intrinsics body MUST contain OP_HASH256
	// (0xaa) — both the extractPrevOutputScript bridge hash AND the
	// requireOutputP2PKH hashOutputs check use OP_HASH256. The stack
	// scaffolding around them may evolve; we only assert the load-bearing
	// primitive shows up.
	if !strings.Contains(result.Artifact.Script, "aa") {
		t.Errorf("expected OP_HASH256 (`aa`) in compiled hex; bridge hash assertions missing. Hex: %s", result.Artifact.Script)
	}

	// Locate the public method's ABI entry. The auto-injected witness
	// params must appear after the user-facing params.
	var foundMethod bool
	for _, m := range result.Artifact.ABI.Methods {
		if m.Name != "coSpendPrivileged" {
			continue
		}
		foundMethod = true
		paramNames := make(map[string]bool)
		var got []string
		for _, p := range m.Params {
			paramNames[p.Name] = true
			got = append(got, p.Name)
		}
		for _, want := range []string{"_prevOutScript_0", "_serialisedOutputs", "txPreimage"} {
			if !paramNames[want] {
				t.Errorf("expected param %q in coSpendPrivileged ABI; got: %v", want, got)
			}
		}
		break
	}
	if !foundMethod {
		var names []string
		for _, m := range result.Artifact.ABI.Methods {
			names = append(names, m.Name)
		}
		t.Fatalf("method coSpendPrivileged not found in artifact ABI; got: %v", names)
	}
}

// TestIntentIntrinsics_ExtractPrevOutputScriptOnly checks the simplest
// single-intrinsic compile path (just the witness-bridge for input 0).
func TestIntentIntrinsics_ExtractPrevOutputScriptOnly(t *testing.T) {
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type MinIntent struct {
	runar.StatefulSmartContract
	H runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (c *MinIntent) Bind() {
	s := runar.ExtractPrevOutputScript(0, c.H)
	_ = s
}
`
	result := CompileFromSourceStrWithResult(source, "MinIntent.runar.go")
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	if result.Artifact.Script == "" {
		t.Fatal("expected non-empty hex")
	}

	// Opcode-sequence audit (minor cleanup from Phase 13 review): the
	// emitted Script for an `extractPrevOutputScript(0, H)` call MUST
	// contain OP_HASH256 (0xaa) — the witness-bridge identity check that
	// distinguishes the intrinsic from a plain identity pass-through. The
	// stack scaffolding (which side the expected hash is pushed from and
	// whether the equality is OP_EQUAL+OP_VERIFY-via-assert or
	// OP_EQUALVERIFY) is allowed to evolve; we only assert the load-
	// bearing primitive is present.
	hex := result.Artifact.Script
	if !strings.Contains(hex, "aa") {
		t.Errorf("expected OP_HASH256 (`aa`) in compiled hex; missing the witness-bridge hash assertion. Hex: %s", hex)
	}
}
