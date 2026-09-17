package runar

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Issue #119: FromUtxo / FromTxId filled the constructor argument list with 0
// placeholders instead of parsing the real values baked into the deployed
// locking script. Every restored contract then operated on zeros, so the ANF
// interpreter computed the wrong state continuation (readonly ctor params feed
// the continuation formula) and adjustCodeSepOffset computed a zero shift,
// yielding the wrong OP_CODESEPARATOR / OP_PUSH_TX offset. Restored stateful
// spends were unspendable.
//
// Fix: restoreConstructorArgs parses the deployed script via
// ExtractConstructorArgs and orders the values by ABI param (paramIndex).
func TestFromUtxo_RestoresRealConstructorArgs_Issue119(t *testing.T) {
	// `tag` is a readonly ctor slot whose value participates in the bump
	// continuation formula; `count` is mutable state (OP_RETURN section).
	src := `import { StatefulSmartContract } from 'runar-lang';
class Restorable extends StatefulSmartContract {
  readonly tag: bigint;
  count: bigint;
  constructor(tag: bigint, count: bigint) { super(tag, count); this.tag = tag; this.count = count; }
  public bump(): void { this.count = this.count + this.tag; }
}`
	tmp := t.TempDir() + "/Restorable.runar.ts"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	signer, _ := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	addr, _ := signer.GetAddress()
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 500000, Script: BuildP2PKHScript(addr)})

	const tag = int64(42)
	c := NewRunarContract(&art, []interface{}{tag, int64(0)})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 50000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if c.currentUtxo == nil {
		t.Fatal("expected a live contract UTXO after deploy")
	}

	// Restore from the deployed UTXO — must recover tag=42, not the 0 placeholder.
	restored, err := FromUtxo(&art, *c.currentUtxo)
	if err != nil {
		t.Fatalf("FromUtxo: %v", err)
	}
	if len(restored.constructorArgs) == 0 {
		t.Fatal("restored contract has no constructor args")
	}
	gotTag := toInt64(restored.constructorArgs[0])
	if gotTag != tag {
		t.Errorf("restored tag = %d, want %d (issue #119: fromUtxo must parse the real baked-in ctor arg, not 0)", gotTag, tag)
	}
}
