package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R-012 / CL-BUG-093, end to end through the real CLI.
//
// The attack, exactly as the reviewer built it:
//
//	1. a contract calling verifySP1FRI WITHOUT the directive is REFUSED on the
//	   `--source` path;
//	2. the same contract WITH `@acknowledgeUnsoundSP1FriVerifier` compiles, and
//	   `--emit-ir` dumps its ANF IR — which contains ZERO trace of the directive;
//	3. feeding that IR to `--ir` used to compile clean, exit 0, no warning,
//	   producing byte-for-byte the script step 1 refused to emit.
//
// Step 3 must now be refused, and must become possible again only when the
// INVOKER acknowledges it on the command line.

const sp1FriGuardContract = `package contracts

import runar "github.com/icellan/runar/packages/runar-go"

%s
type Sp1CliGuard struct {
	runar.SmartContract
	Sp1VKeyHash runar.ByteString ` + "`runar:\"readonly\"`" + `
}

func (v *Sp1CliGuard) Verify(
	proofBlob runar.ByteString,
	publicValues runar.ByteString,
) {
	runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, v.Sp1VKeyHash))
}
`

func TestCLI_IRPath_RefusesUnsoundSP1FriVerifier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()

	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}

	writeContract := func(name, directive string) string {
		p := filepath.Join(tmp, name)
		body := strings.Replace(sp1FriGuardContract, "%s", directive, 1)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return p
	}

	noAck := writeContract("NoAck.runar.go", "// (no acknowledgement)")
	acked := writeContract("Acked.runar.go", "// @acknowledgeUnsoundSP1FriVerifier")

	// Step 1 — the source path refuses without the directive. This is the
	// control for the refusal itself: if it ever stops firing, the IR-path
	// test below proves nothing.
	out, err := exec.Command(binPath, "--source", noAck, "--hex").CombinedOutput()
	if err == nil {
		t.Fatalf("source path ACCEPTED an unacknowledged verifySP1FRI contract")
	}
	if !strings.Contains(string(out), "REFUSING") {
		t.Fatalf("source-path refusal message changed; got:\n%s", string(out))
	}

	// Step 2 — the acknowledged variant emits IR, and that IR carries no trace
	// of the acknowledgement. This is why a loader-side guard cannot consult a
	// flag: there is none, and there cannot be one that means anything.
	irPath := filepath.Join(tmp, "acked.ir.json")
	irJSON, err := exec.Command(binPath, "--source", acked, "--emit-ir").Output()
	if err != nil {
		t.Fatalf("--emit-ir on the acknowledged contract failed: %v", err)
	}
	if strings.Contains(string(irJSON), "cknowledge") || strings.Contains(string(irJSON), "ckUnsound") {
		t.Fatalf("ANF IR unexpectedly carries the acknowledgement; this test's premise " +
			"(and the guard's design) needs revisiting")
	}
	if !strings.Contains(string(irJSON), "verifySP1FRI") {
		t.Fatalf("ANF IR does not name verifySP1FRI; the observable the guard keys on is gone")
	}
	if err := os.WriteFile(irPath, irJSON, 0o644); err != nil {
		t.Fatalf("writing IR: %v", err)
	}

	// Step 3 — the bypass. Feeding that IR to `--ir` must now be refused.
	out, err = exec.Command(binPath, "--ir", irPath, "--hex").CombinedOutput()
	if err == nil {
		t.Fatalf("--ir ACCEPTED the known-unsound SP1 FRI verifier (%d bytes of output); "+
			"the entire frontend, refusal included, was bypassed", len(out))
	}
	if !strings.Contains(string(out), "REFUSING") {
		t.Fatalf("--ir refusal message must name the refusal; got:\n%s", string(out))
	}

	// Step 4 — the escape hatch, and the proof that the guard only gates, never
	// changes bytes: acknowledging on the command line produces exactly the
	// script the acknowledged source path produces.
	irHex, err := exec.Command(binPath, "--ir", irPath, "--hex", "--acknowledge-unsound-sp1-fri").Output()
	if err != nil {
		t.Fatalf("--ir with --acknowledge-unsound-sp1-fri must compile: %v", err)
	}
	srcHex, err := exec.Command(binPath, "--source", acked, "--hex").Output()
	if err != nil {
		t.Fatalf("acknowledged --source compile failed: %v", err)
	}
	if strings.TrimSpace(string(irHex)) != strings.TrimSpace(string(srcHex)) {
		t.Fatalf("acknowledged --ir script diverged from the acknowledged --source script "+
			"(%d vs %d hex chars); the guard must gate, not transform",
			len(strings.TrimSpace(string(irHex))), len(strings.TrimSpace(string(srcHex))))
	}
}

// TestCLI_IRPath_OrdinaryContractUnaffected is the negative control at the CLI
// layer: a contract with nothing to do with SP1 must round-trip
// source -> --emit-ir -> --ir to the same bytes it always did, with no flag.
func TestCLI_IRPath_OrdinaryContractUnaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}

	src := filepath.Join(tmp, "P2PKH.runar.ts")
	if err := os.WriteFile(src, []byte(p2pkhTSForIRGuard), 0o644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	irJSON, err := exec.Command(binPath, "--source", src, "--emit-ir").Output()
	if err != nil {
		t.Fatalf("--emit-ir: %v", err)
	}
	irPath := filepath.Join(tmp, "p2pkh.ir.json")
	if err := os.WriteFile(irPath, irJSON, 0o644); err != nil {
		t.Fatalf("writing IR: %v", err)
	}

	irHex, err := exec.Command(binPath, "--ir", irPath, "--hex").Output()
	if err != nil {
		t.Fatalf("ordinary IR must still compile through --ir: %v", err)
	}
	if len(strings.TrimSpace(string(irHex))) == 0 {
		t.Fatal("ordinary IR produced an empty script")
	}
}

const p2pkhTSForIRGuard = `import { SmartContract, assert, hash160, checkSig } from 'runar-lang';
import type { Addr, Sig, PubKey } from 'runar-lang';

export class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`
