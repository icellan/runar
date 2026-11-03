package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// F-183: three silent CLI flag-precedence bugs in compilers/go/main.go.
//
//  1. `--source X --ir Y` silently compiled from --source and dropped --ir,
//     with no diagnostic (the `if *sourceFile != "" {...} else {...}` branch
//     at the old L192-197 never checked for both being set).
//  2. `--hex --asm` together silently picked --hex and dropped --asm, same
//     shape of bug (`if *hexOnly {...} else if *asmOnly {...}` at the old
//     L253-257).
//  3. `--emit-ir --emit-source-map <path>` printed the IR and returned
//     unconditionally (old L163-172) *before* the --emit-source-map block
//     (old L217-234) ran, so the source map file was never written — no
//     error, no file, just silence. `--emit-ir-to` (a different flag) does
//     NOT have this bug: it writes its file and falls through to the normal
//     compile, which is what lets the later --emit-source-map block run.
//
// This test file proves all three were bugs (red) and are fixed (green). It
// does not touch any conformance fixture or golden: none of the existing
// CLI call sites (conformance/source-map/run.ts, go-only-parity.test.ts,
// ir-artifact-roundtrip.test.ts, ...) ever pass these conflicting flag pairs
// to the Go binary, so no golden byte output changes.

// buildPrecedenceCLI builds the compilers/go binary once per test into tmp.
func buildPrecedenceCLI(t *testing.T, tmp string) string {
	t.Helper()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}
	return binPath
}

const precedenceSource = `import { SmartContract, assert } from 'runar-lang';

export class PrecedenceProbe extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
  }
}
`

// TestCLI_SourceAndIR_Conflict_Refused: passing both --source and --ir must
// be refused with a non-zero exit and a diagnostic naming both flags, not
// silently compile from --source while dropping --ir.
func TestCLI_SourceAndIR_Conflict_Refused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildPrecedenceCLI(t, tmp)

	srcPath := filepath.Join(tmp, "PrecedenceProbe.runar.ts")
	if err := os.WriteFile(srcPath, []byte(precedenceSource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	// Produce a valid IR file from the same source so a bug that silently
	// prefers --source (rather than refusing) would otherwise exit 0.
	irPath := filepath.Join(tmp, "PrecedenceProbe.ir.json")
	emit := exec.Command(bin, "--source", srcPath, "--emit-ir")
	irOut, err := emit.Output()
	if err != nil {
		t.Fatalf("--emit-ir setup step failed: %v", err)
	}
	if err := os.WriteFile(irPath, irOut, 0o644); err != nil {
		t.Fatalf("write IR: %v", err)
	}

	cmd := exec.Command(bin, "--source", srcPath, "--ir", irPath, "--hex")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("--source and --ir together must be refused (non-zero exit); got success with output: %s", string(out))
	}
	if !strings.Contains(string(out), "--source") || !strings.Contains(string(out), "--ir") {
		t.Fatalf("diagnostic must name both conflicting flags, got: %q", string(out))
	}
}

// TestCLI_HexAndAsm_Conflict_Refused: passing both --hex and --asm must be
// refused, not silently resolved to --hex.
func TestCLI_HexAndAsm_Conflict_Refused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildPrecedenceCLI(t, tmp)

	srcPath := filepath.Join(tmp, "PrecedenceProbe.runar.ts")
	if err := os.WriteFile(srcPath, []byte(precedenceSource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cmd := exec.Command(bin, "--source", srcPath, "--hex", "--asm")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("--hex and --asm together must be refused (non-zero exit); got success with output: %s", string(out))
	}
	if !strings.Contains(string(out), "--hex") || !strings.Contains(string(out), "--asm") {
		t.Fatalf("diagnostic must name both conflicting flags, got: %q", string(out))
	}
}

// TestCLI_EmitIR_WithSourceMap_WritesSourceMap: `--emit-ir` together with
// `--emit-source-map <path>` must actually write the source map file. At
// HEAD, --emit-ir prints the IR and returns before the --emit-source-map
// block ever runs, so the file is silently never created.
func TestCLI_EmitIR_WithSourceMap_WritesSourceMap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildPrecedenceCLI(t, tmp)

	srcPath := filepath.Join(tmp, "PrecedenceProbe.runar.ts")
	if err := os.WriteFile(srcPath, []byte(precedenceSource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	smPath := filepath.Join(tmp, "sm.json")

	cmd := exec.Command(bin, "--source", srcPath, "--emit-ir", "--emit-source-map", smPath)
	irOut, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("--source --emit-ir --emit-source-map must still exit 0, got %v\nstderr: %s", err, stderr)
	}
	if strings.TrimSpace(string(irOut)) == "" {
		t.Fatalf("--emit-ir must still print the IR to stdout when combined with --emit-source-map")
	}
	if _, statErr := os.Stat(smPath); statErr != nil {
		t.Fatalf("--emit-source-map file was not written when combined with --emit-ir: %v", statErr)
	}
	smBytes, err := os.ReadFile(smPath)
	if err != nil {
		t.Fatalf("read source map: %v", err)
	}
	if !strings.Contains(string(smBytes), "mappings") {
		t.Fatalf("source map file must carry the {\"mappings\":[...]} wrapper, got: %q", string(smBytes))
	}
}
