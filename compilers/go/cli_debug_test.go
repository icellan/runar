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
// final: fail without crashing the wrapper.
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
	if err != nil {
		// A falsy script is not a wrapper error; the wrapper should still
		// exit 0 and report the failure in its final line.
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("debug on OP_0 must exit 0 (wrapper-wise), got: %v\nstderr: %s", err, stderr)
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
