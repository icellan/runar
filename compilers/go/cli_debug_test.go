package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLI_Debug_TrivialScript builds the compilers/go binary and exercises
// the `debug` subcommand against a one-byte locking script (OP_1 = 0x51).
// The trace must:
//   - exit with code 0,
//   - emit at least one "step=…" line,
//   - report final: pass (OP_1 leaves [1] on the stack).
//
// G-6 (audits/cross-language-completeness-20260514.md §5.1).
func TestCLI_Debug_TrivialScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	// OP_1 — pushes 1 onto the stack, which is truthy → final: pass.
	cmd := exec.Command(binPath, "debug", "--script", "51")
	stdout, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("debug on OP_1 must exit 0, got: %v\nstderr: %s", err, stderr)
	}

	out := string(stdout)
	if !strings.Contains(out, "step=1") {
		t.Fatalf("expected step=1 line in trace, got:\n%s", out)
	}
	if !strings.Contains(out, "final: pass") {
		t.Fatalf("expected 'final: pass' (OP_1 evaluates truthy), got:\n%s", out)
	}
}

// TestCLI_Debug_RequiresInput verifies the subcommand rejects an invocation
// with neither --script nor --artifact.
func TestCLI_Debug_RequiresInput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	cmd := exec.Command(binPath, "debug")
	if err := cmd.Run(); err == nil {
		t.Fatalf("debug with no input must exit non-zero; got success")
	}
}

// TestCLI_Debug_FailingScript verifies a falsy script (OP_0) reports
// final: fail and exits non-zero, so CI / scripts can rely on the exit
// status (F-221). It does not prove anything about the interpreter itself.
func TestCLI_Debug_FailingScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	// OP_0 — pushes empty bytes, which is falsy.
	cmd := exec.Command(binPath, "debug", "--script", "00")
	stdout, err := cmd.Output()
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("debug on OP_0 must exit non-zero, got: %v\nstdout: %s", err, string(stdout))
	}
	out := string(stdout)
	if !strings.Contains(out, "final: fail") {
		t.Fatalf("expected 'final: fail' for OP_0, got:\n%s", out)
	}
}

// TestCLI_Debug_Artifact verifies the --artifact flag loads the 'script'
// field from a JSON artifact.
func TestCLI_Debug_Artifact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	artifactPath := filepath.Join(tmp, "trivial.json")
	if err := os.WriteFile(artifactPath, []byte(`{"script":"51"}`), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	cmd := exec.Command(binPath, "debug", "--artifact", artifactPath)
	stdout, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("debug --artifact must exit 0, got: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(string(stdout), "final: pass") {
		t.Fatalf("expected 'final: pass' from --artifact OP_1, got:\n%s", string(stdout))
	}
}

// TestCLI_Debug_ConflictingFlags verifies --script and --artifact are
// alternatives (see the usage string: "[--script <hex> | --artifact
// <path>]"), not combinable. N-235 (mirrors F-386, landed for Rust in
// debug_subcommand.rs): runDebug only consulted --artifact when --script
// was empty (`if locking == "" && *artifactPath != ""`), so passing both
// flags together silently ran --script and discarded --artifact, exiting 0.
//
// Proves: debug with both flags set exits non-zero with a diagnostic
// naming both --script and --artifact.
// Does not prove: which flag "should" win in a world where the conflict
// becomes a documented precedence instead of a refusal — only that it is
// refused with a diagnostic naming both, per the brief's testable
// assertion.
func TestCLI_Debug_ConflictingFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	artifactPath := filepath.Join(tmp, "other.json")
	if err := os.WriteFile(artifactPath, []byte(`{"script":"52"}`), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	cmd := exec.Command(binPath, "debug", "--script", "51", "--artifact", artifactPath)
	stdout, err := cmd.Output()
	if err == nil {
		t.Fatalf("debug with both --script and --artifact must exit non-zero; got success, stdout:\n%s", string(stdout))
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an *exec.ExitError, got: %v", err)
	}
	stderr := string(ee.Stderr)
	if !strings.Contains(stderr, "--script") || !strings.Contains(stderr, "--artifact") {
		t.Fatalf("expected a diagnostic naming both --script and --artifact, got:\n%s", stderr)
	}
}

// TestCLI_Debug_Artifact_SourceMap verifies the `debug --artifact` trace
// annotates each covered opcode's step line with the source location
// (file:line:column) resolved from the artifact's `sourceMap.mappings`,
// mirroring the resolution packages/runar-testing/src/source-map.ts
// performs for `runar debug` (TS): the nearest mapping whose opcodeIndex is
// <= the opcode's sequential step index.
//
// F-309: previously the artifact unmarshal struct only had a `Script`
// field, so `sourceMap` was silently discarded and no trace line ever
// carried a source location, regardless of how rich the artifact's map was.
//
// This test proves: a non-empty sourceMap on the artifact causes the Go
// debugger to print the mapped file:line:column for the opcodes it covers.
// It does NOT prove: that the mapping is correct for a real compiled
// contract (the artifact here is a hand-built fixture, not compiler
// output), or that opcode indices are resolved consistently when a
// non-empty --unlock script precedes the locking script (TS's own resolver
// counts steps across both contexts; this test only exercises the
// locking-script-only case, which is unambiguous).
func TestCLI_Debug_Artifact_SourceMap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	// Script "5152" = OP_1 OP_2 — two opcodes, so each gets its own mapping.
	artifactPath := filepath.Join(tmp, "mapped.json")
	artifactJSON := `{
		"script": "5152",
		"sourceMap": {
			"mappings": [
				{"opcodeIndex": 0, "sourceFile": "Foo.runar.ts", "line": 5, "column": 3},
				{"opcodeIndex": 1, "sourceFile": "Foo.runar.ts", "line": 6, "column": 7}
			]
		}
	}`
	if err := os.WriteFile(artifactPath, []byte(artifactJSON), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	cmd := exec.Command(binPath, "debug", "--artifact", artifactPath)
	stdout, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("debug --artifact must exit 0, got: %v\nstderr: %s", err, stderr)
	}

	out := string(stdout)
	if !strings.Contains(out, "src=Foo.runar.ts:5:3") {
		t.Fatalf("expected step 1 to carry src=Foo.runar.ts:5:3, got:\n%s", out)
	}
	if !strings.Contains(out, "src=Foo.runar.ts:6:7") {
		t.Fatalf("expected step 2 to carry src=Foo.runar.ts:6:7, got:\n%s", out)
	}
}

// TestCLI_Debug_PrintsErrorWhenNoOpcodesExecuted: a locking script whose first
// push is truncated fails before any opcode runs. The trace is empty, so the
// per-step "error:" line never prints; the interpreter error must still be
// surfaced (N-098). Proves the error text reaches stdout; does not pin its
// exact wording, which belongs to the go-sdk interpreter.
func TestCLI_Debug_PrintsErrorWhenNoOpcodesExecuted(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	// 0x05 announces a 5-byte push with no data following.
	cmd := exec.Command(binPath, "debug", "--script", "05")
	out, _ := cmd.CombinedOutput()
	s := string(out)
	if !strings.Contains(s, "(no opcodes executed)") {
		t.Fatalf("expected the no-opcodes marker, got:\n%s", s)
	}
	if !strings.Contains(s, "error:") {
		t.Fatalf("expected the interpreter error to be printed when no opcodes executed, got:\n%s", s)
	}
}
