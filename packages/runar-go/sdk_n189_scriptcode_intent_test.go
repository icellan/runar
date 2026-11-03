package runar

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// N-189: the off-chain scriptCode that PrepareCall hands the ANF interpreter
// (what extractScriptCode(txPreimage) returns while the SDK predicts the
// post-state) must be the BIP-143 scriptCode field of the preimage the call
// actually signs. That field is the SPENT UTXO's locking script after the
// OP_CODESEPARATOR — code AND the `OP_RETURN <state>` tail. R67 built it from
// the bare template codePart, which omits the state tail, so a method whose
// post-state depends on its own scriptCode committed a continuation the
// covenant's hashOutputs check rejects.
//
// What this proves: for a contract whose new state is
// len(extractScriptCode(txPreimage)), the committed state equals the length
// of the scriptCode field in the signed preimage (bytes 104..len-52), and the
// go-sdk script interpreter accepts the spend.
// What it does not prove: contracts reading other preimage fields, or extra
// contract inputs of a multi-input call (each is spent by its own preimage).

const n189ScLenSrc = `import { StatefulSmartContract, extractScriptCode, len } from 'runar-lang';

class ScLen extends StatefulSmartContract {
  n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public rec(): void {
    this.n = len(extractScriptCode(this.txPreimage));
  }
}`

func TestPrepareCall_ScriptCodeIntentIncludesStateTail_N189(t *testing.T) {
	tmp := t.TempDir() + "/ScLen.runar.ts"
	if err := os.WriteFile(tmp, []byte(n189ScLenSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile ScLen: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	signer, err := NewLocalSigner(c19PrivKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    500000,
		Script:      BuildP2PKHScript(addr),
	})

	c := NewRunarContract(&art, []interface{}{int64(0)})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 50000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	prepared, err := c.PrepareCall("rec", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	preimage, err := hex.DecodeString(prepared.Preimage)
	if err != nil || len(preimage) < 157 {
		t.Fatalf("expected a BIP-143 preimage, got %q (%v)", prepared.Preimage, err)
	}
	// scriptCode field (CompactSize prefix included) = preimage[104 : len-52].
	signedScriptCodeLen := int64(len(preimage) - 104 - 52)

	if _, _, err := c.FinalizeCall(prepared, map[int]string{}, provider); err != nil {
		t.Fatalf("FinalizeCall (state prediction disagrees with the signed scriptCode?): %v", err)
	}
	if got := toInt64(c.GetState()["n"]); got != signedScriptCodeLen {
		t.Fatalf("committed n = %d, want len(signed preimage scriptCode) = %d", got, signedScriptCodeLen)
	}

	txs := provider.GetBroadcastedTxs()
	if len(txs) != 2 {
		t.Fatalf("expected 2 broadcasts (deploy+call), got %d", len(txs))
	}
	deployTx, err := transaction.NewTransactionFromHex(txs[0])
	if err != nil {
		t.Fatalf("parse deploy tx: %v", err)
	}
	callTx, err := transaction.NewTransactionFromHex(txs[1])
	if err != nil {
		t.Fatalf("parse call tx: %v", err)
	}
	if execErr := interpreter.NewEngine().Execute(
		interpreter.WithTx(callTx, 0, deployTx.Outputs[0]),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	); execErr != nil {
		t.Fatalf("call spend rejected by the go-sdk script interpreter: %v", execErr)
	}
}
