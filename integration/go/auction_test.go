//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/bsv-blockchain/go-sdk/script"
)

func deployAuction(t *testing.T, auctioneer, bidder *helpers.Wallet, highestBid, deadline int64) (*runar.RunarContract, *helpers.Wallet) {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/auction/Auction.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile auction: %v", err)
	}
	t.Logf("Auction script: %d bytes", len(artifact.Script)/2)

	// Constructor params: auctioneer, highestBidder, highestBid, deadline
	contract := runar.NewRunarContract(artifact, []interface{}{
		auctioneer.PubKeyHex(), bidder.PubKeyHex(), int64(highestBid), int64(deadline),
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

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract, funder
}

func TestAuction_Close(t *testing.T) {
	// Deploy auction, then close it with the auctioneer's signature.
	// Uses method index 1 (close).
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()

	contract, _ := deployAuction(t, auctioneer, bidder, 1000, 0)

	// Get the deployed UTXO via SDK, convert to helper UTXO for raw spending
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	// Build spend TX: close pays out to auctioneer
	receiverScript := auctioneer.P2PKHScript()
	spendTx, err := helpers.BuildSpendTx(utxo, receiverScript, 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}

	sigHex, err := helpers.SignInput(spendTx, 0, auctioneer.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	// close(sig: Sig) -- method index 1
	// OP_PUSH_TX for stateful
	opPushTxSigHex, preimageHex, err := helpers.SignOpPushTx(spendTx, 0)
	if err != nil {
		t.Fatalf("op_push_tx: %v", err)
	}
	opPushTxSigBytes, _ := hex.DecodeString(opPushTxSigHex)
	preimageBytes, _ := hex.DecodeString(preimageHex)

	// Unlocking: <opPushTxSig> <sig> <txPreimage> <methodIndex=1>
	unlockHex := helpers.EncodePushBytes(opPushTxSigBytes) +
		helpers.EncodePushBytes(sigBytes) +
		helpers.EncodePushBytes(preimageBytes) +
		helpers.EncodeMethodIndex(1) // close

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	txid := helpers.AssertTxAccepted(t, spendTx.Hex())
	helpers.AssertTxInBlock(t, txid)
}

func TestAuction_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/auction/Auction.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "Auction" {
		t.Fatalf("expected contract name Auction, got %s", artifact.ContractName)
	}
	t.Logf("Auction compiled: %d bytes", len(artifact.Script)/2)
}

func TestAuction_Deploy(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/auction/Auction.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{
		auctioneer.PubKeyHex(), bidder.PubKeyHex(), int64(1000), int64(1000000),
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
	t.Logf("deployed: %s", txid)
}

func TestAuction_DeployZeroBid(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()
	contract, _ := deployAuction(t, auctioneer, bidder, 0, 1000000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with zero bid")
}

func TestAuction_DeploySameKey(t *testing.T) {
	wallet := helpers.NewWallet()
	contract, _ := deployAuction(t, wallet, wallet, 1000, 1000000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with same key as auctioneer and bidder")
}

func TestAuction_WrongSigner_Rejected(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()
	attacker := helpers.NewWallet()

	contract, _ := deployAuction(t, auctioneer, bidder, 1000, 0)

	// Get the deployed UTXO via SDK, convert to helper UTXO for raw spending
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	// Attacker tries to close -- should fail checkSig
	spendTx, err := helpers.BuildSpendTx(utxo, attacker.P2PKHScript(), 4500)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}

	sigHex, err := helpers.SignInput(spendTx, 0, attacker.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	opPushTxSigHex, preimageHex, err := helpers.SignOpPushTx(spendTx, 0)
	if err != nil {
		t.Fatalf("op_push_tx: %v", err)
	}
	opPushTxSigBytes, _ := hex.DecodeString(opPushTxSigHex)
	preimageBytes, _ := hex.DecodeString(preimageHex)

	// Unlocking: <opPushTxSig> <sig> <txPreimage> <methodIndex=1>
	unlockHex := helpers.EncodePushBytes(opPushTxSigBytes) +
		helpers.EncodePushBytes(sigBytes) +
		helpers.EncodePushBytes(preimageBytes) +
		helpers.EncodeMethodIndex(1) // close

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	helpers.AssertTxRejected(t, spendTx.Hex())
}
