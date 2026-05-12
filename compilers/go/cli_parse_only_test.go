package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLI_ParseOnly_ValidSource builds the compilers/go binary and exercises
// the `--parse-only` flag against a tiny valid `.runar.ts` contract. The
// flag must:
//   - exit with code 0,
//   - emit the literal string "parser ok" on stdout,
//   - emit nothing else (no IR, no hex, no JSON).
//
// `--parse-only` is the wire used by `conformance/runner/runner.ts` (the
// `--parser-only` universal-frontend coverage check) to assert that every
// compiler can parse every fixture's every format without invoking the
// (slower) full emit pipeline. A regression in this flag silently breaks
// the all-tier parser-only matrix in CI.
//
// GAP-013 (audits/cross-language-completeness-20260510.md, Section 4 / B8).
func TestCLI_ParseOnly_ValidSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()

	// 1. Build the CLI binary into the temp dir.
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "." // compilers/go (this test's package directory)
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOut))
	}

	// 2. Use the in-tree P2PKH fixture as our valid source. It is exercised
	//    by every cross-format conformance run, so any parse failure on it
	//    indicates a real frontend regression unrelated to this test's
	//    setup.
	srcPath, err := filepath.Abs(filepath.Join("..", "..", "examples", "ts", "p2pkh", "P2PKH.runar.ts"))
	if err != nil {
		t.Fatalf("resolve source path: %v", err)
	}
	if _, err := os.Stat(srcPath); err != nil {
		t.Fatalf("fixture missing at %s: %v", srcPath, err)
	}

	// 3. Invoke `<bin> --source <src> --parse-only` and capture stdout/stderr.
	cmd := exec.Command(binPath, "--source", srcPath, "--parse-only")
	stdout, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("--parse-only on valid source must exit 0, got: %v\nstderr: %s", err, stderr)
	}

	got := strings.TrimSpace(string(stdout))
	if got != "parser ok" {
		t.Fatalf("expected stdout to be exactly \"parser ok\", got %q", got)
	}
}

// TestCLI_ParseOnly_InvalidSource verifies that `--parse-only` reports
// parse failures via a non-zero exit code AND stderr diagnostics, instead
// of silently succeeding. A stray non-zero exit on a bad source is what
// the conformance runner relies on to detect frontend regressions.
func TestCLI_ParseOnly_InvalidSource(t *testing.T) {
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

	// Source with a deliberate syntax error: unterminated class brace,
	// missing semicolons, orphan `=` token. The TS parser must reject this.
	badSrc := "class Broken extends SmartContract { = = = "
	srcPath := filepath.Join(tmp, "Broken.runar.ts")
	if err := os.WriteFile(srcPath, []byte(badSrc), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cmd := exec.Command(binPath, "--source", srcPath, "--parse-only")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("--parse-only on invalid source must exit non-zero; got success.\nCombined output:\n%s", string(out))
	}
	// Some kind of diagnostic must appear (stderr is included in CombinedOutput).
	if len(out) == 0 {
		t.Fatalf("expected diagnostic output on parse failure, got empty stdout+stderr")
	}
}

// TestCLI_ParseOnly_RequiresSourceFlag verifies that `--parse-only` without
// `--source` is rejected (since we can't parse without input). This guards
// against the flag silently no-op'ing if a future refactor breaks the
// argument-validation branch in main.go.
func TestCLI_ParseOnly_RequiresSourceFlag(t *testing.T) {
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

	// `--parse-only` with no `--source`: should fail (the no-source branch
	// triggers usage and a non-zero exit before reaching the parse-only
	// guard, but either way exit code must be non-zero).
	cmd := exec.Command(binPath, "--parse-only")
	if err := cmd.Run(); err == nil {
		t.Fatalf("--parse-only without --source must exit non-zero; got success")
	}
}
