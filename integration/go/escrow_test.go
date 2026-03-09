//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

func deployEscrow(t *testing.T, buyer, seller, arbiter *helpers.Wallet, funder *helpers.Wallet) *runar.RunarContract {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/escrow/Escrow.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile escrow: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{
		buyer.PubKeyHex(), seller.PubKeyHex(), arbiter.PubKeyHex(),
	})

	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract
}

// spendEscrowDualSig builds an unlocking script with two signatures + method index.
// The new escrow contract uses dual-signature methods:
//   - release(sellerSig, arbiterSig) — method index 0
//   - refund(buyerSig, arbiterSig) — method index 1
func spendEscrowDualSig(t *testing.T, contract *runar.RunarContract, signer1, signer2 *helpers.Wallet, methodIdx int) string {
	t.Helper()
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverScript := signer1.P2PKHScript()
	spendTx, err := helpers.BuildSpendTx(utxo, receiverScript, 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}

	sig1Hex, err := helpers.SignInput(spendTx, 0, signer1.PrivKey)
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}
	sig1Bytes, _ := hex.DecodeString(sig1Hex)

	sig2Hex, err := helpers.SignInput(spendTx, 0, signer2.PrivKey)
	if err != nil {
		t.Fatalf("sign2: %v", err)
	}
	sig2Bytes, _ := hex.DecodeString(sig2Hex)

	// Unlocking script: <sig1> <sig2> <methodIndex>
	unlockHex := helpers.EncodePushBytes(sig1Bytes) +
		helpers.EncodePushBytes(sig2Bytes) +
		helpers.EncodeMethodIndex(methodIdx)

	spendHex, err := helpers.SpendContract(utxo, unlockHex, receiverScript, 4500)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}
	return spendHex
}

func TestEscrow_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/escrow/Escrow.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "Escrow" {
		t.Fatalf("expected contract name Escrow, got %s", artifact.ContractName)
	}
	t.Logf("Escrow compiled: %d bytes", len(artifact.Script)/2)
}

func TestEscrow_DeployThreePubKeys(t *testing.T) {
	buyer := helpers.NewWallet()
	seller := helpers.NewWallet()
	arbiter := helpers.NewWallet()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/escrow/Escrow.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{
		buyer.PubKeyHex(), seller.PubKeyHex(), arbiter.PubKeyHex(),
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("deployed with 3 distinct pubkeys: %s", txid)
}

func TestEscrow_DeploySameKey(t *testing.T) {
	wallet := helpers.NewWallet()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/escrow/Escrow.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{
		wallet.PubKeyHex(), wallet.PubKeyHex(), wallet.PubKeyHex(),
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("deployed with same key for all roles: %s", txid)
}

// release(sellerSig, arbiterSig) — method index 0
func TestEscrow_Release(t *testing.T) {
	buyer, seller, arbiter := helpers.NewWallet(), helpers.NewWallet(), helpers.NewWallet()
	contract := deployEscrow(t, buyer, seller, arbiter, seller)
	spendHex := spendEscrowDualSig(t, contract, seller, arbiter, 0)
	txid := helpers.AssertTxAccepted(t, spendHex)
	helpers.AssertTxInBlock(t, txid)
}

// refund(buyerSig, arbiterSig) — method index 1
func TestEscrow_Refund(t *testing.T) {
	buyer, seller, arbiter := helpers.NewWallet(), helpers.NewWallet(), helpers.NewWallet()
	contract := deployEscrow(t, buyer, seller, arbiter, buyer)
	spendHex := spendEscrowDualSig(t, contract, buyer, arbiter, 1)
	txid := helpers.AssertTxAccepted(t, spendHex)
	helpers.AssertTxInBlock(t, txid)
}

// release with wrong signer — should fail checkSig
func TestEscrow_WrongSigner_Rejected(t *testing.T) {
	buyer, seller, arbiter := helpers.NewWallet(), helpers.NewWallet(), helpers.NewWallet()
	contract := deployEscrow(t, buyer, seller, arbiter, seller)
	// Use buyer's sig where seller's is expected — should fail
	spendHex := spendEscrowDualSig(t, contract, buyer, arbiter, 0)
	helpers.AssertTxRejected(t, spendHex)
}

func TestEscrow_InvalidMethodIndex_Rejected(t *testing.T) {
	buyer, seller, arbiter := helpers.NewWallet(), helpers.NewWallet(), helpers.NewWallet()
	contract := deployEscrow(t, buyer, seller, arbiter, seller)
	// Method index 5 doesn't exist — only 0 (release) and 1 (refund)
	spendHex := spendEscrowDualSig(t, contract, seller, arbiter, 5)
	helpers.AssertTxRejected(t, spendHex)
}
