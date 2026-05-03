//go:build integration

package integration

import (
	"fmt"
	"regexp"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// BSV-21 token integration tests — port of integration/ts/bsv21-token.test.ts.
//
// BSV-21 (v2) tokens use deploy+mint as a single operation and reference a
// per-token ID derived from the deploy outpoint (`<txid>_0`). Transfers
// inscribe a JSON payload that names the token ID and amount; the underlying
// lock is still standard P2PKH so the spend itself is a normal Bitcoin
// signature check.

var bsv21Artifact *runar.RunarArtifact
var bsv21Once sync.Once

func getBSV21Artifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	bsv21Once.Do(func() {
		var err error
		bsv21Artifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/bsv21-token/BSV21Token.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile BSV21Token: %v", err)
		}
	})
	return bsv21Artifact
}

func TestBSV21_DeployMint(t *testing.T) {
	artifact := getBSV21Artifact(t)
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

	dec := "18"
	sym := "RNR"
	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(runar.BSV21DeployMint("1000000", &dec, &sym, nil))

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		t.Fatalf("get tx: %v", err)
	}
	obj := readInscriptionJSON(t, tx.Outputs[0].Script)
	if obj["p"] != "bsv-20" {
		t.Fatalf("p: got %v, want bsv-20", obj["p"])
	}
	if obj["op"] != "deploy+mint" {
		t.Fatalf("op: got %v, want deploy+mint", obj["op"])
	}
	if obj["amt"] != "1000000" {
		t.Fatalf("amt: got %v, want 1000000", obj["amt"])
	}
	if obj["dec"] != dec {
		t.Fatalf("dec: got %v, want %s", obj["dec"], dec)
	}
	if obj["sym"] != sym {
		t.Fatalf("sym: got %v, want %s", obj["sym"], sym)
	}

	tokenID := fmt.Sprintf("%s_0", txid)
	if !regexp.MustCompile(`^[0-9a-f]{64}_0$`).MatchString(tokenID) {
		t.Fatalf("token id %s does not match `<txid>_0`", tokenID)
	}
}

func TestBSV21_TransferReferencesTokenID(t *testing.T) {
	artifact := getBSV21Artifact(t)
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

	// Deploy+Mint to create a token ID.
	sym := "TST"
	deployContract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	deployContract.WithInscription(runar.BSV21DeployMint("500", nil, &sym, nil))
	deployTxid, _, err := deployContract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy mint: %v", err)
	}
	tokenID := fmt.Sprintf("%s_0", deployTxid)

	// Inscribe a transfer referencing the token ID.
	transferContract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	transferContract.WithInscription(runar.BSV21Transfer(tokenID, "100"))
	transferTxid, _, err := transferContract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1})
	if err != nil {
		t.Fatalf("deploy transfer: %v", err)
	}

	tx, err := provider.GetTransaction(transferTxid)
	if err != nil {
		t.Fatalf("get tx: %v", err)
	}
	obj := readInscriptionJSON(t, tx.Outputs[0].Script)
	if obj["op"] != "transfer" {
		t.Fatalf("op: got %v, want transfer", obj["op"])
	}
	if obj["id"] != tokenID {
		t.Fatalf("id: got %v, want %s", obj["id"], tokenID)
	}
	if obj["amt"] != "100" {
		t.Fatalf("amt: got %v, want 100", obj["amt"])
	}
}

func TestBSV21_SpendTransferUTXO(t *testing.T) {
	artifact := getBSV21Artifact(t)
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
	contract.WithInscription(runar.BSV21Transfer(
		"0000000000000000000000000000000000000000000000000000000000000001_0",
		"50",
	))

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	spendTxid, _, err := contract.Call("unlock", []interface{}{nil, nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if len(spendTxid) != 64 {
		t.Fatalf("expected 64-char spend txid, got %d", len(spendTxid))
	}
}

func TestBSV21_RoundTripViaFromTxId(t *testing.T) {
	artifact := getBSV21Artifact(t)
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

	dec := "2"
	sym := "ABC"
	icon := "https://example.com/icon.png"
	contract := runar.NewRunarContract(artifact, []interface{}{wallet.PubKeyHashHex()})
	contract.WithInscription(runar.BSV21DeployMint("999", &dec, &sym, &icon))

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
	obj := readInscriptionJSON(t, reconnected.GetLockingScript())
	if obj["op"] != "deploy+mint" {
		t.Fatalf("reconnected op: got %v, want deploy+mint", obj["op"])
	}
	if obj["sym"] != sym {
		t.Fatalf("reconnected sym: got %v, want %s", obj["sym"], sym)
	}
	if obj["icon"] != icon {
		t.Fatalf("reconnected icon: got %v, want %s", obj["icon"], icon)
	}
	if reconnected.GetLockingScript() != contract.GetLockingScript() {
		t.Fatalf("locking script mismatch after reconnection")
	}
}
