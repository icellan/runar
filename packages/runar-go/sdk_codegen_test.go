package runar

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// N-148: GenerateGo's Mustache renderer expanded the innermost section first
// against the ROOT context, so every section nested inside {{#methods}}
// ({{#isTerminal}}, {{#isStatefulMethod}}, {{#userParams}}, ...) was looked up
// in the root map, found missing, and wiped. Every generated method came out
// with no user params and an empty body (a Go compile error for any method
// with results).
//
// What these tests prove:
//   - GenerateGo for the shared conformance/sdk-codegen fixtures counter.json
//     (stateful, mixed terminal/non-terminal) and p2pkh.json (stateless, Sig
//     param) emits each method with its user params and a real body, and the
//     generated source COMPILES (go vet) against this runar-go package.
//   - For REAL compiled Counter and P2PKH artifacts, the generated wrapper is
//     compiled and run: Deploy + Increment / Unlock go through the
//     validating (default fail-closed) MockProvider, which executes every
//     known input through the go-sdk script interpreter.
//
// What they do not prove:
//   - Cross-SDK structural parity with the TS reference (only the Go output
//     shape is asserted), the stateful-escrow / inscribed fixtures, or the
//     Prepare/Finalize external-signer flow at runtime (compiled, not run).
//   - Full Mustache spec compliance: the renderer only supports what the
//     embedded template uses.

func loadCodegenFixture(t *testing.T, name string) *RunarArtifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "conformance", "sdk-codegen", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(data, &art); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	return &art
}

func assertContains(t *testing.T, src, want string) {
	t.Helper()
	if !strings.Contains(src, want) {
		t.Fatalf("generated Go is missing:\n  %s\n--- generated ---\n%s", want, src)
	}
}

// codegenTempModule writes the given files into a fresh Go module that
// depends on this checkout's runar-go (and compilers/go) via replace
// directives, and returns its directory. GOWORK is off and the proxy is
// disabled so resolution is from the local checkout + module cache only.
func codegenTempModule(t *testing.T, files map[string]string) (string, []string) {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	goMod := "module codegencheck\n\ngo 1.26\n\n" +
		"require github.com/icellan/runar/packages/runar-go v0.0.0\n\n" +
		"replace github.com/icellan/runar/packages/runar-go => " + filepath.Join(repoRoot, "packages", "runar-go") + "\n" +
		"replace github.com/icellan/runar/compilers/go => " + filepath.Join(repoRoot, "compilers", "go") + "\n"
	files["go.mod"] = goMod
	var sum []byte
	for _, p := range []string{
		filepath.Join(repoRoot, "packages", "runar-go", "go.sum"),
		filepath.Join(repoRoot, "compilers", "go", "go.sum"),
	} {
		b, err := os.ReadFile(p)
		if err == nil {
			sum = append(sum, b...)
		}
	}
	files["go.sum"] = string(sum)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
	return dir, env
}

func runGo(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// vetGenerated compiles (go vet type-checks) the generated wrapper alone.
func vetGenerated(t *testing.T, src string) {
	t.Helper()
	dir, env := codegenTempModule(t, map[string]string{
		"wrapper.go": src,
		"main.go":    "package main\n\nfunc main() {}\n",
	})
	runGo(t, dir, env, "vet", ".")
}

func TestGenerateGo_CounterFixture_MethodsHaveParamsAndBodies(t *testing.T) {
	src := GenerateGo(loadCodegenFixture(t, "counter.json"))

	assertContains(t, src, "func (c *CounterContract) Increment(Amount *big.Int, provider runar.Provider, signer runar.Signer, options *CounterStatefulCallOptions) (string, *runar.TransactionData, error) {")
	assertContains(t, src, `return c.inner.Call("increment", []interface{}{ Amount }, provider, signer, options.toCallOptions())`)
	assertContains(t, src, "func (c *CounterContract) Reset(provider runar.Provider, signer runar.Signer, outputs []TerminalOutput) (string, *runar.TransactionData, error) {")
	assertContains(t, src, `return c.inner.Call("reset", []interface{}{  }, provider, signer, opts)`)
	assertContains(t, src, "func NewCounterContract(artifact *runar.RunarArtifact, Count *big.Int) *CounterContract {")
	if strings.Contains(src, "{{") {
		t.Fatalf("generated Go still contains unrendered Mustache tags:\n%s", src)
	}

	vetGenerated(t, src)
}

func TestGenerateGo_P2PKHFixture_MethodsHaveParamsAndBodies(t *testing.T) {
	src := GenerateGo(loadCodegenFixture(t, "p2pkh.json"))

	// Sig is SDK-supplied: hidden from Unlock, passed as nil in the args.
	assertContains(t, src, "func (c *P2PKHContract) Unlock(PubKey string, provider runar.Provider, signer runar.Signer, outputs []TerminalOutput) (string, *runar.TransactionData, error) {")
	assertContains(t, src, `return c.inner.Call("unlock", []interface{}{ nil, PubKey }, provider, signer, opts)`)
	assertContains(t, src, "func (c *P2PKHContract) PrepareUnlock(PubKey string, provider runar.Provider, signer runar.Signer, outputs []TerminalOutput) (*runar.PreparedCall, error) {")
	assertContains(t, src, `return c.inner.PrepareCall("unlock", []interface{}{ nil, PubKey }, provider, signer, opts)`)
	assertContains(t, src, "func (c *P2PKHContract) FinalizeUnlock(prepared *runar.PreparedCall, Sig string, provider runar.Provider) (string, *runar.TransactionData, error) {")
	assertContains(t, src, "return c.inner.FinalizeCall(prepared, map[int]string{ 0: Sig }, provider)")
	if strings.Contains(src, "StatefulCallOptions") {
		t.Fatalf("stateless P2PKH wrapper must not emit a StatefulCallOptions type:\n%s", src)
	}
	if strings.Contains(src, "{{") {
		t.Fatalf("generated Go still contains unrendered Mustache tags:\n%s", src)
	}

	vetGenerated(t, src)
}

// compileCodegenSource compiles a Rúnar TS source with the Go compiler and
// returns the artifact JSON and the decoded artifact.
func compileCodegenSource(t *testing.T, fileName, src string) ([]byte, *RunarArtifact) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), fileName)
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	return out, &art
}

// codegenDriverPrelude is shared by the end-to-end drivers: it loads the
// artifact, funds a LocalSigner on a validating MockProvider and exposes a
// fail() helper. Every failure exits non-zero, which fails runGo.
const codegenDriverPrelude = `package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	runar "github.com/icellan/runar/packages/runar-go"
)

var _ = big.NewInt
var _ = hex.EncodeToString

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func setup() (*runar.RunarArtifact, *runar.MockProvider, *runar.LocalSigner, string) {
	data, err := os.ReadFile("artifact.json")
	if err != nil {
		fail("read artifact: %v", err)
	}
	var art runar.RunarArtifact
	if err := json.Unmarshal(data, &art); err != nil {
		fail("unmarshal artifact: %v", err)
	}
	signer, err := runar.NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		fail("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	p := runar.NewMockProvider("testnet") // validating (fail-closed) by default
	p.AddUtxo(addr, runar.UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    500_000,
		Script:      runar.BuildP2PKHScript(addr),
	})
	return &art, p, signer, addr
}
`

func TestGenerateGo_Counter_EndToEndOnValidatingMockProvider(t *testing.T) {
	artJSON, art := compileCodegenSource(t, "Counter.runar.ts", `import { StatefulSmartContract } from 'runar-lang';
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment(amount: bigint): void {
    this.count = this.count + amount;
  }
}`)
	wrapper := GenerateGo(art)

	driver := codegenDriverPrelude + `
func main() {
	art, p, signer, _ := setup()
	c := NewCounterContract(art, big.NewInt(5))
	if _, _, err := c.Deploy(p, signer, runar.DeployOptions{Satoshis: 1_000}); err != nil {
		fail("deploy rejected: %v", err)
	}
	if _, _, err := c.Increment(big.NewInt(3), p, signer, nil); err != nil {
		fail("Increment rejected: %v", err)
	}
	if got := p.LastValidatedInputCount(); got < 2 {
		fail("Increment broadcast validated only %d input(s)", got)
	}
	if got := fmt.Sprint(c.Contract().GetState()["count"]); got != "8" {
		fail("count after Increment(3) = %s, want 8", got)
	}
	fmt.Println("CODEGEN_E2E_OK")
}
`
	dir, env := codegenTempModule(t, map[string]string{
		"wrapper.go":    wrapper,
		"main.go":       driver,
		"artifact.json": string(artJSON),
	})
	if out := runGo(t, dir, env, "run", "."); !strings.Contains(out, "CODEGEN_E2E_OK") {
		t.Fatalf("driver did not report success:\n%s", out)
	}
}

func TestGenerateGo_P2PKH_EndToEndOnValidatingMockProvider(t *testing.T) {
	artJSON, art := compileCodegenSource(t, "P2PKH.runar.ts", `import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}`)
	wrapper := GenerateGo(art)

	driver := codegenDriverPrelude + `
func main() {
	art, p, signer, addr := setup()
	pubKeyHex, err := signer.GetPublicKey()
	if err != nil {
		fail("pubkey: %v", err)
	}
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		fail("decode pubkey: %v", err)
	}
	pkh := hex.EncodeToString([]byte(runar.Hash160(runar.PubKey(raw))))
	c := NewP2PKHContract(art, pkh)
	if _, _, err := c.Deploy(p, signer, runar.DeployOptions{Satoshis: 10_000}); err != nil {
		fail("deploy rejected: %v", err)
	}
	outs := []TerminalOutput{{Satoshis: 9_000, Address: addr}}
	if _, _, err := c.Unlock(pubKeyHex, p, signer, outs); err != nil {
		fail("Unlock rejected: %v", err)
	}
	if got := p.LastValidatedInputCount(); got < 1 {
		fail("Unlock broadcast validated %d input(s)", got)
	}
	fmt.Println("CODEGEN_E2E_OK")
}
`
	dir, env := codegenTempModule(t, map[string]string{
		"wrapper.go":    wrapper,
		"main.go":       driver,
		"artifact.json": string(artJSON),
	})
	if out := runGo(t, dir, env, "run", "."); !strings.Contains(out, "CODEGEN_E2E_OK") {
		t.Fatalf("driver did not report success:\n%s", out)
	}
}
