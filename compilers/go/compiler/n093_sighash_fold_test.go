package compiler

import (
	"encoding/json"
	"strings"
	"testing"
)

// N-093 — the Go constant folder dropped ANFMethod.SigHashType.
//
// foldMethod rebuilt ir.ANFMethod field-by-field and supplied only 4 of its 5
// fields, so a `@sighash` directive survived fold-OFF but vanished fold-ON.
// Constant folding is ON by default in the shipped CLI, so every artifact the
// SDK actually reads lost the flag.
//
// The field is tagged `json:"-"`, so the cross-tier ANF IR comparison
// structurally cannot observe it, and the pre-existing sighash coverage
// (compiler/sighash_codegen_test.go) runs exclusively fold-OFF via compileOK's
// hardcoded DisableConstantFolding: true. Neither gate could go red.
//
// Every test below states its fold mode explicitly.

// n093Compile compiles src under an explicit fold mode.
// foldOn = true  -> constant folding ENABLED  (the shipped CLI default)
// foldOn = false -> constant folding DISABLED (the golden-replay mode)
func n093Compile(t *testing.T, src string, foldOn bool) *CompileResult {
	t.Helper()
	r := CompileFromSourceStrWithResult(src, "Counter.runar.ts", CompileOptions{
		DisableConstantFolding: !foldOn,
	})
	if !r.Success {
		t.Fatalf("foldOn=%v: compile failed: %v", foldOn, diagMessages(r))
	}
	return r
}

// n093SdkResolveSigHashType replicates, verbatim, the resolution the Go SDK
// performs in packages/runar-go/sdk_contract.go#methodSigHashType. That package
// imports compilers/go, so it cannot be imported back here (import cycle) —
// mirroring the five lines is the closest in-lane reproduction of the consequence.
func n093SdkResolveSigHashType(r *CompileResult, methodName string) int {
	for _, m := range r.Artifact.ABI.Methods {
		if m.Name == methodName && m.IsPublic && m.SigHashType != nil {
			return *m.SigHashType
		}
	}
	return 0x41 // SDK default: ALL|FORKID
}

// --- The defect: fold-ON drops the declared mode -------------------------

// FOLD-ON. This is the mode the shipped CLI runs in and the one that shipped broken.
func TestN093_SighashTypeSurvivesConstantFolding(t *testing.T) {
	r := n093Compile(t, counterOut("/** @sighash SINGLE|FORKID */"), true)
	sig := abiSigHash(r, "bump")
	if sig == nil {
		t.Fatalf("fold-ON: abi.methods[bump].sigHashType is absent; want 0x43 (SINGLE|FORKID)")
	}
	if *sig != 0x43 {
		t.Fatalf("fold-ON: abi.methods[bump].sigHashType = 0x%x, want 0x43", *sig)
	}
}

// FOLD-OFF control: this passed before the fix and must keep passing.
func TestN093_SighashTypeFoldOffUnchanged(t *testing.T) {
	r := n093Compile(t, counterOut("/** @sighash SINGLE|FORKID */"), false)
	sig := abiSigHash(r, "bump")
	if sig == nil || *sig != 0x43 {
		t.Fatalf("fold-OFF: abi.methods[bump].sigHashType = %v, want 0x43", sig)
	}
}

// Both modes must agree. A mode-dependent ABI is the bug in its most general form.
func TestN093_SighashTypeIdenticalAcrossFoldModes(t *testing.T) {
	on := abiSigHash(n093Compile(t, counterOut("/** @sighash SINGLE|FORKID */"), true), "bump")
	off := abiSigHash(n093Compile(t, counterOut("/** @sighash SINGLE|FORKID */"), false), "bump")
	switch {
	case on == nil && off == nil:
		t.Fatalf("both modes dropped sigHashType; want 0x43")
	case on == nil || off == nil:
		t.Fatalf("sigHashType is fold-mode dependent: fold-ON=%v fold-OFF=%v", on, off)
	case *on != *off:
		t.Fatalf("sigHashType diverges by fold mode: fold-ON=0x%x fold-OFF=0x%x", *on, *off)
	}
}

// --- Controls: a default-mode contract omits the key in BOTH modes -------

func TestN093_DefaultModeOmitsSigHashTypeInBothFoldModes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		directive string
	}{
		{"no directive", ""},
		{"explicit ALL|FORKID", "/** @sighash ALL|FORKID */"},
	} {
		for _, foldOn := range []bool{true, false} {
			r := n093Compile(t, counterOut(tc.directive), foldOn)
			if sig := abiSigHash(r, "bump"); sig != nil {
				t.Errorf("%s foldOn=%v: sigHashType = 0x%x, want absent (default ALL|FORKID)",
					tc.name, foldOn, *sig)
			}
			// The key must be absent from the serialised ABI, not merely nil-valued.
			blob, err := json.Marshal(r.Artifact.ABI)
			if err != nil {
				t.Fatalf("marshal ABI: %v", err)
			}
			if strings.Contains(string(blob), "sigHashType") {
				t.Errorf("%s foldOn=%v: serialised ABI carries a sigHashType key: %s",
					tc.name, foldOn, blob)
			}
		}
	}
}

// --- Consequence: the SDK builds the preimage under the wrong flags ------

// The locking script asserts the declared mode inline (OP_PUSH_TX compares the
// preimage's sighash-type field against a pushed constant). The SDK reads
// abi.sigHashType to decide which flags to build that preimage under. When
// folding drops the ABI field the two disagree: the script demands 0x43, the
// SDK signs 0x41, and the spend can never satisfy the covenant.
//
// Runs in BOTH fold modes; only fold-ON could fail before the fix.
func TestN093_SdkPreimageFlagsMatchScriptAssertion(t *testing.T) {
	for _, foldOn := range []bool{true, false} {
		r := n093Compile(t, counterOut("/** @sighash SINGLE|FORKID */"), foldOn)

		// The script embeds the 0x43 assertion regardless of fold mode:
		// `01 43 7e` = PUSHDATA1(0x43) OP_CAT. Codegen reads the check_preimage
		// node's sighashFlag, not ANFMethod.SigHashType, so it was never affected.
		if !strings.Contains(r.ScriptHex, "01437e") {
			t.Fatalf("foldOn=%v: locking script does not assert SINGLE|FORKID (0x43)", foldOn)
		}
		if strings.Contains(r.ScriptHex, "01417e") {
			t.Fatalf("foldOn=%v: locking script unexpectedly asserts ALL|FORKID (0x41)", foldOn)
		}

		// What the SDK would actually sign under.
		got := n093SdkResolveSigHashType(r, "bump")
		if got != 0x43 {
			t.Errorf("foldOn=%v: SDK would build the BIP-143 preimage under sighash 0x%x, "+
				"but the locking script asserts 0x43 — the covenant can never be satisfied "+
				"and the UTXO is unspendable via the SDK", foldOn, got)
		}
	}
}

// --- Script bytes must not move in either fold mode ----------------------

// SigHashType never reaches codegen, so the fix must be byte-neutral.
// Pins the fold-OFF script against the checked-in TS golden and asserts
// fold-ON produces the same bytes for this contract.
func TestN093_ScriptHexUnchangedInBothFoldModes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		directive string
		golden    string
	}{
		{"default", "", counterDefaultScript},
		{"SINGLE|FORKID", "/** @sighash SINGLE|FORKID */", counterSingleScript},
	} {
		off := n093Compile(t, counterOut(tc.directive), false).ScriptHex
		if off != tc.golden {
			t.Errorf("%s fold-OFF script != TS golden:\n got %s\nwant %s", tc.name, off, tc.golden)
		}
		on := n093Compile(t, counterOut(tc.directive), true).ScriptHex
		if on != off {
			t.Errorf("%s: fold-ON script diverges from fold-OFF:\n  on %s\n off %s", tc.name, on, off)
		}
	}
}
