//go:build integration

package integration

import (
	"encoding/hex"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

var p2pkhArtifact *runar.RunarArtifact
var p2pkhOnce sync.Once

func getP2PKHArtifact(t *testing.T) *runar.RunarArtifact {
	p2pkhOnce.Do(func() {
		var err error
		p2pkhArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/p2pkh/P2PKH.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile P2PKH: %v", err)
		}
	})
	return p2pkhArtifact
}

func deployP2PKH(t *testing.T, owner *helpers.Wallet, provider *helpers.BatchRPCProvider) (*runar.RunarContract, *helpers.BatchRPCProvider, runar.Signer) {
	t.Helper()

	artifact := getP2PKHArtifact(t)
	t.Logf("P2PKH script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{owner.PubKeyHashHex()})

	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err := helpers.FundWallet(owner, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract, provider, signer
}

func TestP2PKH_ValidUnlock(t *testing.T) {
	owner := helpers.NewWallet()
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	contract, _, _ := deployP2PKH(t, owner, provider)

	// For stateless contracts with checkSig, we need raw spending because
	// the sig must be computed over the final spending transaction.
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := owner.P2PKHScript()
	spendTx, err := helpers.BuildSpendTx(utxo, receiverScript, 4500)
	if err != nil {
		t.Fatalf("build spend tx: %v", err)
	}

	sigHex, err := helpers.SignInput(spendTx, 0, owner.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	unlockHex := helpers.EncodePushBytes(sigBytes) + helpers.EncodePushBytes(owner.PubKeyBytes)
	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 4500)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	txid := helpers.AssertTxAccepted(t, spendHex)
	t.Logf("spend TX accepted: %s", txid)
}

func TestP2PKH_WrongKey_Rejected(t *testing.T) {
	owner := helpers.NewWallet()
	attacker := helpers.NewWallet()

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	contract, _, _ := deployP2PKH(t, owner, provider)
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	spendTx, err := helpers.BuildSpendTx(utxo, attacker.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}
	sigHex, err := helpers.SignInput(spendTx, 0, attacker.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	unlockHex := helpers.EncodePushBytes(sigBytes) + helpers.EncodePushBytes(attacker.PubKeyBytes)
	spendHex, err := helpers.SpendContract(utxo, unlockHex, attacker.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

func TestP2PKH_DeployDifferentPubKeyHash(t *testing.T) {
	owner1 := helpers.NewWallet()
	owner2 := helpers.NewWallet()

	artifact := getP2PKHArtifact(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	// Deploy with owner1
	contract1 := runar.NewRunarContract(artifact, []interface{}{owner1.PubKeyHashHex()})
	helpers.RPCCall("importaddress", owner1.Address, "", false)
	_, err := helpers.FundWallet(owner1, 1.0)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	signer1, _ := helpers.SDKSignerFromWallet(owner1)
	txid1, _, err := contract1.Deploy(provider, signer1, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy1: %v", err)
	}

	// Deploy with owner2
	contract2 := runar.NewRunarContract(artifact, []interface{}{owner2.PubKeyHashHex()})
	helpers.RPCCall("importaddress", owner2.Address, "", false)
	_, err = helpers.FundWallet(owner2, 1.0)
	if err != nil {
		t.Fatalf("fund2: %v", err)
	}
	signer2, _ := helpers.SDKSignerFromWallet(owner2)
	txid2, _, err := contract2.Deploy(provider, signer2, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy2: %v", err)
	}

	if txid1 == txid2 {
		t.Fatalf("expected different txids, got same: %s", txid1)
	}
	t.Logf("owner1 txid: %s, owner2 txid: %s", txid1, txid2)
}

func TestP2PKH_WrongSig_Rejected(t *testing.T) {
	owner := helpers.NewWallet()
	wrongSigner := helpers.NewWallet()

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	contract, _, _ := deployP2PKH(t, owner, provider)
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	spendTx, err := helpers.BuildSpendTx(utxo, owner.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}
	sigHex, err := helpers.SignInput(spendTx, 0, wrongSigner.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	unlockHex := helpers.EncodePushBytes(sigBytes) + helpers.EncodePushBytes(owner.PubKeyBytes)
	spendHex, err := helpers.SpendContract(utxo, unlockHex, owner.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("spend contract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}
