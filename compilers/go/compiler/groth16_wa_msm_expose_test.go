package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGroth16WAMSM_PublicInputExposed compiles a stateful contract that
// uses AssertGroth16WitnessAssistedWithMSM and then reads the first
// public-input scalar via Groth16PublicInput(0), asserting it equals a
// contract-held pinned value. The test verifies that:
//
//  1. Compilation succeeds end-to-end (parse -> typecheck -> anf -> stack
//     -> emit).
//  2. The emitted script is non-trivial (contains the huge MSM preamble
//     as well as the body's equality check).
//  3. Changing the public-input index (0 vs 4) produces DIFFERENT scripts
//     — if the intrinsic still silently returned a zero literal (the
//     pre-R1b behaviour), the index would not be observable and the two
//     scripts would be identical.
func TestGroth16WAMSM_PublicInputExposed(t *testing.T) {
	vkPath := sp1VKPath(t)

	build := func(index string) string {
		return `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type MSMPinCheck struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *MSMPinCheck) Advance(nextCounter runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(` + index + `) == c.Pinned)
	c.Counter = nextCounter
}
`
	}

	tmpDir := t.TempDir()
	compile := func(idx string) string {
		srcPath := filepath.Join(tmpDir, "MSMPinCheck_"+idx+".runar.go")
		if err := os.WriteFile(srcPath, []byte(build(idx)), 0o644); err != nil {
			t.Fatalf("write source: %v", err)
		}
		art, err := CompileFromSource(srcPath, CompileOptions{Groth16WAVKey: vkPath})
		if err != nil {
			t.Fatalf("compile failed for index %s: %v", idx, err)
		}
		if art == nil {
			t.Fatalf("artifact is nil for index %s", idx)
		}
		if len(art.Script) == 0 {
			t.Fatalf("empty script for index %s", idx)
		}
		return art.Script
	}

	scriptZero := compile("0")
	scriptFour := compile("4")

	if scriptZero == scriptFour {
		t.Fatal("Groth16PublicInput(0) and Groth16PublicInput(4) produced identical scripts; the index is not observable in the emitted code (regression: public-input scalars are no longer exposed to the method body)")
	}

	// Sanity-check the script is large: the MSM-binding preamble alone is
	// >1 MB in hex. A zero-return stub would emit ~a few kilobytes.
	const minSize = 100_000
	if len(scriptZero) < minSize {
		t.Fatalf("script for index=0 is suspiciously small (%d hex chars); expected >= %d — MSM preamble did not run", len(scriptZero), minSize)
	}
}

// TestGroth16WAMSM_PublicInputRejectsNonConstIndex verifies the codegen
// rejects non-compile-time-constant indices. The MSM preamble reserves
// fixed stack slots (_pub_0 .. _pub_4); a runtime index cannot be resolved
// at codegen time.
func TestGroth16WAMSM_PublicInputRejectsNonConstIndex(t *testing.T) {
	vkPath := sp1VKPath(t)

	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type MSMDynamicIdx struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *MSMDynamicIdx) Advance(dynIdx runar.Bigint, nextCounter runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(dynIdx) == c.Pinned)
	c.Counter = nextCounter
}
`
	srcPath := filepath.Join(t.TempDir(), "MSMDynamicIdx.runar.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	_, err := CompileFromSource(srcPath, CompileOptions{Groth16WAVKey: vkPath})
	if err == nil {
		t.Fatal("expected error from runtime-indexed groth16PublicInput; compile succeeded")
	}
	if !strings.Contains(err.Error(), "groth16PublicInput") || !strings.Contains(err.Error(), "compile-time constant") {
		t.Fatalf("expected error message to mention groth16PublicInput and compile-time constant; got: %v", err)
	}
}

// TestGroth16WAMSM_PublicInputRejectsOutOfRange verifies that indices
// outside [0, 4] are rejected at codegen time.
func TestGroth16WAMSM_PublicInputRejectsOutOfRange(t *testing.T) {
	vkPath := sp1VKPath(t)

	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type MSMBadIdx struct {
	runar.StatefulSmartContract

	Pinned  runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
	Counter runar.Bigint
}

func (c *MSMBadIdx) Advance(nextCounter runar.Bigint) {
	runar.AssertGroth16WitnessAssistedWithMSM()
	runar.Assert(runar.Groth16PublicInput(5) == c.Pinned)
	c.Counter = nextCounter
}
`
	srcPath := filepath.Join(t.TempDir(), "MSMBadIdx.runar.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	_, err := CompileFromSource(srcPath, CompileOptions{Groth16WAVKey: vkPath})
	if err == nil {
		t.Fatal("expected error from out-of-range groth16PublicInput(5); compile succeeded")
	}
	if !strings.Contains(err.Error(), "index must be in [0, 4]") {
		t.Fatalf("expected error message to mention index range; got: %v", err)
	}
}
