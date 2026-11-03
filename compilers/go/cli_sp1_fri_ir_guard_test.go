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
// The original attack: a contract calling verifySP1FRI WITH
// `@acknowledgeUnsoundSP1FriVerifier` compiled, `--emit-ir` dumped its IR (no
// trace of the directive), and `--ir` then compiled that IR clean. R-012 made
// `--ir` refuse unless the invoker passed `--acknowledge-unsound-sp1-fri`.
//
// F-007: rewritten to expect refusal everywhere — the SP1 FRI verifier is not
// implemented for v1, so the directive and the flag were removed. Every route
// through the CLI must now refuse: source with or without the old directive,
// --emit-ir of it, and --ir of hand-written IR with or without the old flag.

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

// sp1FriGuardIR is ANF IR reaching the verifier, written by hand: since F-007
// no source route can emit it.
const sp1FriGuardIR = `{"contractName":"Sp1CliGuard","properties":[{"name":"sp1VKeyHash","type":"ByteString","readonly":true}],` +
	`"methods":[{"name":"verify","isPublic":true,"params":[{"name":"proofBlob","type":"ByteString"},{"name":"publicValues","type":"ByteString"}],` +
	`"body":[{"name":"t0","value":{"kind":"load_param","name":"proofBlob"}},{"name":"t1","value":{"kind":"load_param","name":"publicValues"}},` +
	`{"name":"t2","value":{"kind":"load_prop","name":"sp1VKeyHash"}},{"name":"t3","value":{"kind":"call","func":"verifySP1FRI","args":["t0","t1","t2"]}},` +
	`{"name":"t4","value":{"kind":"assert","value":"t3"}}]}]}`

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

	refused := func(what string, args ...string) {
		t.Helper()
		out, err := exec.Command(binPath, args...).CombinedOutput()
		if err == nil {
			t.Fatalf("F-007: %s COMPILED verifySP1FRI (%d bytes of output); v1 must refuse", what, len(out))
		}
		if strings.Contains(string(out), "--acknowledge-unsound-sp1-fri") && !strings.Contains(string(out), "not defined") {
			t.Fatalf("%s: output still advertises the removed override:\n%s", what, string(out))
		}
	}
	mustSay := func(what string, args ...string) {
		t.Helper()
		out, _ := exec.Command(binPath, args...).CombinedOutput()
		if !strings.Contains(string(out), "not implemented for v1") {
			t.Fatalf("%s: refusal must say the verifier is not implemented for v1; got:\n%s", what, string(out))
		}
	}

	// Source path, with and without the old directive.
	refused("--source without directive", "--source", noAck, "--hex")
	mustSay("--source without directive", "--source", noAck, "--hex")
	refused("--source with old directive", "--source", acked, "--hex")
	mustSay("--source with old directive", "--source", acked, "--hex")
	refused("--emit-ir with old directive", "--source", acked, "--emit-ir")

	// IR path, with and without the removed flag.
	irPath := filepath.Join(tmp, "sp1.ir.json")
	if err := os.WriteFile(irPath, []byte(sp1FriGuardIR), 0o644); err != nil {
		t.Fatalf("writing IR: %v", err)
	}
	refused("--ir", "--ir", irPath, "--hex")
	mustSay("--ir", "--ir", irPath, "--hex")
	refused("--ir with removed --acknowledge-unsound-sp1-fri", "--ir", irPath, "--hex", "--acknowledge-unsound-sp1-fri")
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
