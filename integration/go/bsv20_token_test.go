//go:build integration

package integration

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// BSV-20 token integration tests — port of integration/ts/bsv20-token.test.ts.
//
// BSV-20 fungible tokens live as inscriptions on top of P2PKH UTXOs. The
// contract logic is just standard P2PKH; the token semantics (deploy, mint,
// transfer) are encoded in the inscription envelope and interpreted by
// indexers, not the script. These tests verify deploy/mint/transfer JSON
// payloads survive a full round-trip on a regtest node and that the
// underlying P2PKH spend is still accepted.

var bsv20Artifact *runar.RunarArtifact
var bsv20Once sync.Once

func getBSV20Artifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	bsv20Once.Do(func() {
		var err error
		bsv20Artifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/bsv20-token/BSV20Token.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile BSV20Token: %v", err)
		}
	})
	return bsv20Artifact
}

// readInscriptionJSON parses the BSV-20 JSON payload out of the inscription
// embedded in the locking script of the given output.
func readInscriptionJSON(t *testing.T, scriptHex string) map[string]interface{} {
	t.Helper()
	insc := runar.ParseInscriptionEnvelope(scriptHex)
	if insc == nil {
		t.Fatalf("inscription envelope not found in script %s", scriptHex)
	}
	if insc.ContentType != "application/bsv-20" {
		t.Fatalf("contentType: got %q, want application/bsv-20", insc.ContentType)
	}
	raw, err := hex.DecodeString(insc.Data)
	if err != nil {
		t.Fatalf("hex decode inscription data: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("inscription JSON parse: %v\nraw=%s", err, string(raw))
	}
	return obj
}

func deployBSV20Inscription(t *testing.T, insc *runar.Inscription) (string, *runar.RunarContract, *helpers.BatchRPCProvider) {
	t.Helper()
	artifact := getBSV20Artifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(insc)

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return txid, contract, provider
}

func TestBSV20_DeployToken(t *testing.T) {
	tick := "RUNAR"
	max := "21000000"
	lim := "1000"
	txid, _, provider := deployBSV20Inscription(t, runar.BSV20Deploy(tick, max, &lim, nil))
	defer provider.MineAll()

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		t.Fatalf("get tx: %v", err)
	}
	obj := readInscriptionJSON(t, tx.Outputs[0].Script)
	if obj["p"] != "bsv-20" {
		t.Fatalf("p: got %v, want bsv-20", obj["p"])
	}
	if obj["op"] != "deploy" {
		t.Fatalf("op: got %v, want deploy", obj["op"])
	}
	if obj["tick"] != tick {
		t.Fatalf("tick: got %v, want %s", obj["tick"], tick)
	}
	if obj["max"] != max {
		t.Fatalf("max: got %v, want %s", obj["max"], max)
	}
}

func TestBSV20_MintTokens(t *testing.T) {
	tick := "RUNAR"
	amt := "1000"
	txid, _, provider := deployBSV20Inscription(t, runar.BSV20Mint(tick, amt))
	defer provider.MineAll()

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		t.Fatalf("get tx: %v", err)
	}
	obj := readInscriptionJSON(t, tx.Outputs[0].Script)
	if obj["op"] != "mint" {
		t.Fatalf("op: got %v, want mint", obj["op"])
	}
	if obj["amt"] != amt {
		t.Fatalf("amt: got %v, want %s", obj["amt"], amt)
	}
}

func TestBSV20_TransferAndSpend(t *testing.T) {
	tick := "RUNAR"
	amt := "50"

	artifact := getBSV20Artifact(t)
	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(runar.BSV20Transfer(tick, amt))

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	tx, err := provider.GetTransaction(deployTxid)
	if err != nil {
		t.Fatalf("get tx: %v", err)
	}
	obj := readInscriptionJSON(t, tx.Outputs[0].Script)
	if obj["op"] != "transfer" {
		t.Fatalf("op: got %v, want transfer", obj["op"])
	}
	if obj["amt"] != amt {
		t.Fatalf("amt: got %v, want %s", obj["amt"], amt)
	}

	// Spend the 1-sat transfer UTXO via P2PKH unlock.
	spendTxid, _, err := contract.Call("unlock", []interface{}{nil, nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if len(spendTxid) != 64 {
		t.Fatalf("expected 64-char spend txid, got %d", len(spendTxid))
	}
	t.Logf("transfer spent: %s", spendTxid)
}

func TestBSV20_RoundTripViaFromTxId(t *testing.T) {
	tick := "TEST"
	max := "1000"
	dec := "8"

	artifact := getBSV20Artifact(t)
	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(runar.BSV20Deploy(tick, max, nil, &dec))

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	reconnected, err := runar.FromTxId(artifact, txid, 0, provider)
	if err != nil {
		t.Fatalf("fromTxId: %v", err)
	}
	insc := reconnected.GetInscription()
	if insc == nil {
		t.Fatalf("reconnected contract has no inscription")
	}
	if insc.ContentType != "application/bsv-20" {
		t.Fatalf("contentType: got %q, want application/bsv-20", insc.ContentType)
	}
	if reconnected.GetLockingScript() != contract.GetLockingScript() {
		t.Fatalf("locking script mismatch after reconnection")
	}
}
