package runar

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// F-024 (R14): the SDK's ANF interpreter derives the post-call state before
// the tx exists; the covenant re-derives it on-chain. For a contract whose
// state depends on `continuationAmount()` (the injected `_newAmount`) and
// `extractAmount(txPreimage)` (the spent UTXO's satoshis), the SDK must feed
// the interpreter those real values or it computes a different state than the
// script and the call is refused.
//
// Proves: the Go SDK derives `lastDeposit = continuation - input` correctly and
// the resulting spend passes the go-sdk script engine with full tx context.
// Does NOT prove: anything about the other six SDKs.
func TestF024_ContinuationAmount_StateRoundTripsThroughSpend(t *testing.T) {
	src := `class Tip extends StatefulSmartContract {
  lastDeposit: bigint;
  constructor(lastDeposit: bigint) { super(lastDeposit); this.lastDeposit = lastDeposit; }
  public deposit() {
    this.lastDeposit = continuationAmount() - extractAmount(this.txPreimage);
  }
}`
	tmp := t.TempDir() + "/Tip.runar.ts"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile Tip: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 500000, Script: BuildP2PKHScript(addr)})

	c := NewRunarContract(&art, []interface{}{int64(0)})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 10000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, _, err := c.Call("deposit", nil, provider, signer, &CallOptions{Satoshis: 12500}); err != nil {
		t.Fatalf("call deposit: %v", err)
	}
	if got := anfToBigInt(c.state["lastDeposit"]).Int64(); got != 2500 {
		t.Fatalf("lastDeposit = %d, want 2500", got)
	}
	txs := provider.GetBroadcastedTxs()
	deployTx, _ := transaction.NewTransactionFromHex(txs[0])
	callTx, _ := transaction.NewTransactionFromHex(txs[len(txs)-1])
	if got := callTx.Outputs[0].Satoshis; got != 12500 {
		t.Fatalf("continuation satoshis = %d, want 12500", got)
	}
	if err := interpreter.NewEngine().Execute(
		interpreter.WithTx(callTx, 0, deployTx.Outputs[0]),
		interpreter.WithAfterGenesis(), interpreter.WithAfterChronicle(), interpreter.WithForkID(),
	); err != nil {
		t.Fatalf("covenant spend rejected: %v", err)
	}
}
