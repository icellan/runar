package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLI_Groth16WAVKFlag_UnreachableWithoutIt and
// TestCLI_Groth16WAVKFlag_CompilesWithIt cover F-305: the main flag-based
// `--source`/`--ir` compile path (as opposed to the separate `groth16-wa`
// subcommand, which synthesizes a bare fixed-VK verifier and takes no
// source file at all) had no way to set CompileOptions.Groth16WAVKey, so a
// user contract that calls runar.AssertGroth16WitnessAssisted among other
// business logic could never be compiled from the CLI — only from the Go
// library API (see integration/go/helpers.CompileToSDKArtifactWithGroth16WAVKey).
//
// GAP-CX-GAP-004.
//
// What this proves: the `--groth16-wa-vk` flag on the main --source/--ir
// compile path wires through to CompileOptions.Groth16WAVKey end to end —
// a contract calling assertGroth16WitnessAssisted fails without the flag
// (for the documented reason) and succeeds, emitting a script of the
// expected order of magnitude, with it; this holds for both --source and
// --ir inputs.
//
// What this does NOT prove: that the emitted witness-assisted verifier
// script correctly ACCEPTS a real SP1 proof or rejects a tampered one —
// that is covered by TestGroth16WA_EndToEnd_SP1Proof_Script
// (packages/runar-go/bn254witness) and the integration/go regtest suite.
// This test only asserts the CLI reaches the codegen with a usable VK and
// that codegen runs to completion.
func TestCLI_Groth16WAVKFlag_UnreachableWithoutIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	binPath := buildGroth16WAVKFlagCLI(t)
	srcAbs := groth16WAVKFlagSourcePath(t)

	cmd := exec.Command(binPath, "--source", srcAbs, "--hex")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected compilation to fail without --groth16-wa-vk, got exit 0 with output:\n%s", string(out))
	}
	if !strings.Contains(string(out), "no Groth16WAConfig was supplied") {
		t.Fatalf("expected the Groth16WAConfig diagnostic, got:\n%s", string(out))
	}
}

func TestCLI_Groth16WAVKFlag_CompilesWithIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	binPath := buildGroth16WAVKFlagCLI(t)
	srcAbs := groth16WAVKFlagSourcePath(t)

	vkAbs, err := filepath.Abs(filepath.Join("..", "..", "tests", "vectors", "sp1", "v6.0.0", "vk.json"))
	if err != nil {
		t.Fatalf("resolve VK path: %v", err)
	}
	if _, err := os.Stat(vkAbs); err != nil {
		t.Fatalf("fixture VK missing at %s: %v", vkAbs, err)
	}

	cmd := exec.Command(binPath, "--source", srcAbs, "--groth16-wa-vk", vkAbs, "--hex")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected compilation to succeed with --groth16-wa-vk, got: %v\n%s", err, string(out))
	}

	script := strings.TrimSpace(string(out))
	if len(script) == 0 {
		t.Fatal("script hex output is empty")
	}
	// The witness-assisted verifier preamble alone (no on-chain MSM) is a
	// multi-hundred-KB script; a few bytes would mean the preamble was
	// silently skipped rather than emitted.
	scriptBytes := len(script) / 2
	if scriptBytes < 100*1024 {
		t.Errorf("script too small: %d bytes (expected > 100 KB for the witness-assisted preamble)", scriptBytes)
	}
}

// TestCLI_Groth16WAVKFlag_CompilesWithIt_IRPath covers the --ir input mode:
// --groth16-wa-vk must also apply when the contract is fed as pre-lowered
// ANF IR JSON (the conformance runner's primary input mode), not only via
// --source. Both input modes flow through the same buildLowerOptions in
// compilers/go/compiler/compiler.go, but that is an implementation detail
// this test does not rely on — it drives the CLI the same way a real --ir
// caller would.
func TestCLI_Groth16WAVKFlag_CompilesWithIt_IRPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	binPath := buildGroth16WAVKFlagCLI(t)
	srcAbs := groth16WAVKFlagSourcePath(t)

	vkAbs, err := filepath.Abs(filepath.Join("..", "..", "tests", "vectors", "sp1", "v6.0.0", "vk.json"))
	if err != nil {
		t.Fatalf("resolve VK path: %v", err)
	}
	if _, err := os.Stat(vkAbs); err != nil {
		t.Fatalf("fixture VK missing at %s: %v", vkAbs, err)
	}

	// Produce the ANF IR for the contract first (--emit-ir never touches
	// Groth16WAVKey; IR emission happens before stack lowering).
	irPath := filepath.Join(t.TempDir(), "wa.ir.json")
	emitCmd := exec.Command(binPath, "--source", srcAbs, "--emit-ir")
	irOut, err := emitCmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("--emit-ir failed: %v\nstderr: %s", err, stderr)
	}
	if err := os.WriteFile(irPath, irOut, 0644); err != nil {
		t.Fatalf("write IR file: %v", err)
	}

	cmd := exec.Command(binPath, "--ir", irPath, "--groth16-wa-vk", vkAbs, "--hex")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected --ir compilation to succeed with --groth16-wa-vk, got: %v\n%s", err, string(out))
	}

	script := strings.TrimSpace(string(out))
	scriptBytes := len(script) / 2
	if scriptBytes < 100*1024 {
		t.Errorf("script too small: %d bytes (expected > 100 KB for the witness-assisted preamble)", scriptBytes)
	}
}

func buildGroth16WAVKFlagCLI(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "." // compilers/go (this test's package directory)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}
	return binPath
}

func groth16WAVKFlagSourcePath(t *testing.T) string {
	t.Helper()
	// StatelessGroth16WA is the minimal contract that calls
	// runar.AssertGroth16WitnessAssisted: no state, no constructor args,
	// just the Mode 3 preamble plus one trivial assert.
	abs, err := filepath.Abs(filepath.Join("..", "..", "integration", "go", "contracts", "StatelessGroth16WA.runar.go"))
	if err != nil {
		t.Fatalf("resolve source path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixture source missing at %s: %v", abs, err)
	}
	return abs
}
