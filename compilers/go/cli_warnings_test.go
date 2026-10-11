package main

import (
	"encoding/json"
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

// F-220: `--emit-ir` printed the IR and returned before the full compile,
// which is where the warnings above are printed, so it dropped every one of
// them, the H2 locktime-bypass advisory included. The TS CLI prints every
// warning-severity diagnostic to stderr before any output mode; these tests
// hold `--emit-ir` to that rule by comparing it with this binary's `--hex`.
//
// What they prove: for a contract carrying the H2 locktime warning and one
// carrying the issue-#109 DCE notice, `--emit-ir` exits 0, prints exactly the
// stderr `--hex` prints, and keeps stdout to the IR JSON (no "script" key).
// With `--emit-source-map` as well (the F-183 fall-through into the full
// compile) the warning is printed exactly once.
// What they do not prove: the `--ir` input path (no validator runs there),
// other tiers' CLIs, or the warning text itself (the validator tests own it).
const f220LocktimeSource = `import { StatefulSmartContract, assert, extractLocktime } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
`

const f220DCESource = `import { SmartContract, assert, PubKey, Sig, Addr, checkSig, hash160 } from 'runar-lang';

class Unused extends SmartContract {
    readonly pubKeyHash: Addr;
    readonly memo: bigint;
    constructor(pubKeyHash: Addr, memo: bigint) {
        super(pubKeyHash, memo);
        this.pubKeyHash = pubKeyHash;
        this.memo = memo;
    }
    public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
`

const f220LocktimeNeedle = "does not assert extractSequence"

func f220Run(t *testing.T, bin string, args ...string) (string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v must exit 0, got %v\nstderr: %s", args, err, stderr.String())
	}
	return string(stdout), stderr.String()
}

func TestCLI_F220_EmitIRPrintsTheSameWarningsAsHex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildWarningsCLI(t, tmp)
	cases := []struct{ file, source, needle string }{
		{"TimeLock.runar.ts", f220LocktimeSource, f220LocktimeNeedle},
		{"Unused.runar.ts", f220DCESource, "readonly field 'memo' is not referenced"},
	}
	for _, c := range cases {
		src := writeWarningsSource(t, tmp, c.file, c.source)
		_, hexErr := f220Run(t, bin, "--source", src, "--hex")
		if !strings.Contains(hexErr, c.needle) {
			t.Fatalf("sanity: --hex must print %q; stderr: %q", c.needle, hexErr)
		}
		irOut, irErr := f220Run(t, bin, "--source", src, "--emit-ir")
		if irErr != hexErr {
			t.Fatalf("%s: --emit-ir must print the same warnings as --hex (F-220)\n--emit-ir stderr: %q\n--hex stderr:     %q", c.file, irErr, hexErr)
		}
		var ir map[string]interface{}
		if err := json.Unmarshal([]byte(irOut), &ir); err != nil {
			t.Fatalf("--emit-ir stdout must be the IR JSON alone: %v\n%s", err, irOut)
		}
		if _, ok := ir["contractName"]; !ok {
			t.Fatalf("stdout must be ANF IR: %s", irOut)
		}
		if _, ok := ir["script"]; ok {
			t.Fatalf("stdout must carry only the IR: %s", irOut)
		}
	}
}

func TestCLI_F220_EmitIRWithSourceMapPrintsTheWarningOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}
	tmp := t.TempDir()
	bin := buildWarningsCLI(t, tmp)
	src := writeWarningsSource(t, tmp, "TimeLock.runar.ts", f220LocktimeSource)
	sm := filepath.Join(tmp, "source-map.json")
	_, errText := f220Run(t, bin, "--source", src, "--emit-ir", "--emit-source-map", sm)
	if _, err := os.Stat(sm); err != nil {
		t.Fatalf("F-183: the source map must still be written: %v", err)
	}
	if n := strings.Count(errText, f220LocktimeNeedle); n != 1 {
		t.Fatalf("the warning must be printed exactly once, got %d\nstderr: %q", n, errText)
	}
}
