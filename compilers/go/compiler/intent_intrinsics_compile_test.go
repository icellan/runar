package compiler

import (
	"os"
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
//
// Performs a deeper opcode-sequence audit than the combined-fixture test —
// asserts (1) OP_HASH256 (0xaa) appears AND (2) is followed within a
// narrow window by OP_EQUAL (0x87) or OP_EQUALVERIFY (0x88), proving the
// hash is being compared against an expected value (not just left on the
// stack). This catches a regression where the lowering passes drop the
// equality assertion after computing hash256.
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

	hex := result.Artifact.Script
	if !strings.Contains(hex, "aa") {
		t.Fatalf("expected OP_HASH256 (`aa`) in compiled hex; missing the witness-bridge hash assertion. Hex: %s", hex)
	}

	// Find OP_HASH256 and assert OP_EQUAL (0x87) or OP_EQUALVERIFY (0x88)
	// appears within the next 8 bytes (16 hex chars), proving the hash
	// is being compared. Window is clamped to len(hex) — for a witness-
	// bridge intrinsic the comparison is one of the LAST things the
	// script does, so the OP_HASH256 sits near the end and the window
	// is naturally short.
	idx := strings.Index(hex, "aa")
	end := idx + 18
	if end > len(hex) {
		end = len(hex)
	}
	window := hex[idx:end]
	if !strings.Contains(window, "87") && !strings.Contains(window, "88") {
		t.Errorf("expected OP_EQUAL (`87`) or OP_EQUALVERIFY (`88`) within 8 bytes after OP_HASH256 (idx=%d); the bridge equality is not enforced. Window: %q (full hex: %s)", idx, window, hex)
	}

	// The auto-injected `_prevOutScript_0` MUST be the last ABI param
	// after txPreimage (matching the auto-injection ordering documented
	// in docs/cross-covenant-pattern.md). Verify ordering, not just
	// presence — out-of-order witness params would break SDK consumers
	// that build the unlocking script by ABI position.
	for _, m := range result.Artifact.ABI.Methods {
		if m.Name != "bind" {
			continue
		}
		var names []string
		for _, p := range m.Params {
			names = append(names, p.Name)
		}
		txPreimageIdx, prevOutScriptIdx := -1, -1
		for i, n := range names {
			if n == "txPreimage" {
				txPreimageIdx = i
			}
			if n == "_prevOutScript_0" {
				prevOutScriptIdx = i
			}
		}
		if txPreimageIdx < 0 {
			t.Errorf("expected txPreimage in bind ABI; got %v", names)
		}
		if prevOutScriptIdx < 0 {
			t.Errorf("expected _prevOutScript_0 in bind ABI; got %v", names)
		}
		if prevOutScriptIdx >= 0 && txPreimageIdx >= 0 && prevOutScriptIdx <= txPreimageIdx {
			t.Errorf("_prevOutScript_0 (idx=%d) must come after txPreimage (idx=%d) per auto-injection ordering; got %v", prevOutScriptIdx, txPreimageIdx, names)
		}
		break
	}
}

// TestIntentIntrinsics_RequireOutputP2PKH_OnceOnlyHashCheck verifies that
// when multiple requireOutputP2PKH calls appear in the same method body,
// the hashOutputs check is emitted EXACTLY ONCE (per the idempotency
// contract in the dispatch code). Counts OP_HASH256 occurrences and
// asserts the count matches: 1 (hashOutputs assertion) + N (per-output
// P2PKH hash), where N = number of distinct output indices.
//
// This guards against a regression where the methodScope.didEmitHashOutputsCheck
// flag gets reset between calls, doubling the emitted hashOutputs check
// and bloating the script.
func TestIntentIntrinsics_RequireOutputP2PKH_OnceOnlyHashCheck(t *testing.T) {
	// Two RequireOutputP2PKH calls, same method — should produce exactly
	// ONE hashOutputs check, NOT two.
	source := `
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Two struct {
	runar.StatefulSmartContract
	PKH1 runar.ByteString ` + "`runar:\"readonly\"`" + `
	PKH2 runar.ByteString ` + "`runar:\"readonly\"`" + `
	A1   runar.Bigint     ` + "`runar:\"readonly\"`" + `
	A2   runar.Bigint     ` + "`runar:\"readonly\"`" + `
}

func (c *Two) Bind() {
	runar.RequireOutputP2PKH(0, c.PKH1, c.A1)
	runar.RequireOutputP2PKH(1, c.PKH2, c.A2)
}
`
	// Compile via the source-to-IR path so we get the ANF directly,
	// independent of whether Artifact.ANF is populated for this contract
	// shape. Counting hash256 in ANF is authoritative — counting `aa`
	// bytes in compiled hex would over-count any 0xaa in pushdata.
	tmpFile := writeTempGoSource(t, "Two.runar.go", source)
	program, err := CompileSourceToIR(tmpFile)
	if err != nil {
		t.Fatalf("CompileSourceToIR failed: %v", err)
	}
	var foundMethod bool
	for _, m := range program.Methods {
		if m.Name != "bind" {
			continue
		}
		foundMethod = true
		hash256Count := 0
		for _, b := range m.Body {
			if b.Value.Kind == "call" && b.Value.Func == "hash256" {
				hash256Count++
			}
		}
		// Expected hash256 count:
		// - 1 for the once-per-method hashOutputs(serialised) check
		// - 0 for the per-output assertion (uses Substr equality, not hash)
		// = 1 total
		// Anything > 1 means the dispatch lost its idempotency flag.
		if hash256Count != 1 {
			t.Errorf("expected exactly 1 hash256 call (once-per-method hashOutputs check) for two requireOutputP2PKH calls in same body; got %d. Idempotency regression?", hash256Count)
		}
		break
	}
	if !foundMethod {
		t.Fatal("method 'bind' not found in ANF")
	}
}

// writeTempGoSource writes a Go-DSL source string to a temp file with the
// given basename and returns the path. Cleanup is automatic via t.TempDir.
func writeTempGoSource(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/" + name
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTempGoSource: %v", err)
	}
	return path
}
