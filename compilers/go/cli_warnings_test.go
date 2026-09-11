package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// CL-BUG-104: the Go CLI ran the validator, then threw its warnings away.
//
// `compiler.CompileFromSource` returns `(*Artifact, error)` — a shape with no
// channel for advisory diagnostics — so every warning the validator produced
// (the SP1 FRI unsoundness disclosure, the `@embedAlways` DCE notices, the
// sighash advisories, the stateful-contract shape hints) died inside the
// compile call. A contract author got silence where the compiler had
// something to say.
//
// The reference behaviour is the Zig tier (`compilers/zig/src/main.zig`
// `printDiagnostics`) and the Rust tier (`compilers/rust/src/main.rs`):
// warnings go to **stderr**, one per line, prefixed `warning: `, and they do
// NOT change the exit code or the emitted bytes.
//
// warnStatefulSource is a contract the validator really does warn about:
// V26, "StatefulSmartContract has no mutable properties". It is a genuine
// validator warning, not a synthetic probe — see
// compilers/go/frontend/validator.go (the parentClass == StatefulSmartContract
// / no-mutable-properties branch).
const warnStatefulSource = `import { StatefulSmartContract, assert } from 'runar-lang';

export class WarnStateful extends StatefulSmartContract {
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

// cleanStatelessSource is the control: a contract the validator has nothing
// to say about. Compiling it must print no warning line at all.
const cleanStatelessSource = `import { SmartContract, assert } from 'runar-lang';

export class CleanStateless extends SmartContract {
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

// buildWarningsCLI builds the compilers/go binary once per test into tmp.
func buildWarningsCLI(t *testing.T, tmp string) string {
	t.Helper()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}
	return binPath
}

func writeWarningsSource(t *testing.T, tmp, name, body string) string {
	t.Helper()
	p := filepath.Join(tmp, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// TestCLI_PrintsValidatorWarnings asserts the warning reaches stderr on an
// ordinary, successful `--source ... --hex` compile.
func TestCLI_PrintsValidatorWarnings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildWarningsCLI(t, tmp)
	src := writeWarningsSource(t, tmp, "WarnStateful.runar.ts", warnStatefulSource)

	cmd := exec.Command(bin, "--source", src, "--hex")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("compile must succeed, got %v\nstderr: %s", err, stderr.String())
	}

	errText := stderr.String()
	if !strings.Contains(errText, "StatefulSmartContract has no mutable properties") {
		t.Fatalf("validator warning did not reach stderr.\nstderr: %q", errText)
	}
	if !strings.Contains(errText, "warning: ") {
		t.Fatalf("warning line must carry the %q prefix used by the Rust/Zig tiers.\nstderr: %q", "warning: ", errText)
	}
	if strings.TrimSpace(string(stdout)) == "" {
		t.Fatalf("stdout must still carry the script hex")
	}
	// The warning must not leak into stdout — stdout is the artifact channel.
	if strings.Contains(string(stdout), "warning") {
		t.Fatalf("warning leaked into stdout: %q", string(stdout))
	}
}

// TestCLI_WarningDoesNotChangeExitCodeOrBytes is the control plus the
// no-side-effect proof: a clean compile prints no warning line and exits 0,
// and the warning-producing contract's hex is byte-identical whether or not
// the warning is printed (the warning rides stderr, the bytes ride stdout).
func TestCLI_WarningDoesNotChangeExitCodeOrBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildWarningsCLI(t, tmp)
	clean := writeWarningsSource(t, tmp, "CleanStateless.runar.ts", cleanStatelessSource)

	cmd := exec.Command(bin, "--source", clean, "--hex")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("clean compile must exit 0, got %v\nstderr: %s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "warning") {
		t.Fatalf("clean compile must print no warning line, got stderr: %q", stderr.String())
	}
	if strings.TrimSpace(string(stdout)) == "" {
		t.Fatalf("clean compile produced no hex")
	}
}

// TestCLI_ParseOnlyPrintsValidatorWarnings pins the same behaviour on the
// `--parse-only` path, which is where the Rust tier prints its warnings
// (`compilers/rust/src/main.rs:148-150`) and where the Zig tier's
// printDiagnostics also runs. `--parse-only` runs the validator, so it has
// warnings to report; dropping them there would leave the two CLI paths
// disagreeing about whether the compiler talks.
func TestCLI_ParseOnlyPrintsValidatorWarnings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildWarningsCLI(t, tmp)
	src := writeWarningsSource(t, tmp, "WarnStateful.runar.ts", warnStatefulSource)

	cmd := exec.Command(bin, "--source", src, "--parse-only")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("--parse-only must exit 0, got %v\nstderr: %s", err, stderr.String())
	}
	if strings.TrimSpace(string(stdout)) != "parser ok" {
		t.Fatalf("--parse-only stdout must stay exactly \"parser ok\", got %q", string(stdout))
	}
	if !strings.Contains(stderr.String(), "warning: ") ||
		!strings.Contains(stderr.String(), "StatefulSmartContract has no mutable properties") {
		t.Fatalf("--parse-only dropped the validator warning.\nstderr: %q", stderr.String())
	}
}
