//go:build integration

package integration

import (
	"encoding/hex"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/bsv-blockchain/go-sdk/script"
)

var auctionArtifact *runar.RunarArtifact
var auctionOnce sync.Once

func getAuctionArtifact(t *testing.T) *runar.RunarArtifact {
	auctionOnce.Do(func() {
		var err error
		auctionArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/auction/Auction.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Auction: %v", err)
		}
	})
	return auctionArtifact
}

func deployAuction(t *testing.T, auctioneer, bidder *helpers.Wallet, highestBid, deadline int64) (*runar.RunarContract, *helpers.Wallet) {
	t.Helper()

	artifact := getAuctionArtifact(t)
	t.Logf("Auction script: %d bytes", len(artifact.Script)/2)

	// Constructor params: auctioneer, highestBidder, highestBid, deadline
	contract := runar.NewRunarContract(artifact, []interface{}{
		auctioneer.PubKeyHex(), bidder.PubKeyHex(), int64(highestBid), int64(deadline),
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, errF := helpers.FundWallet(funder, 1.0)
	if errF != nil {
		t.Fatalf("fund: %v", errF)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
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

	// deadline=0 allows close at any block time (locktime always satisfied).
	contract, _ := deployAuction(t, auctioneer, bidder, 1000, 0)

	// close(sig) via SDK terminal call — method 1. The close method verifies
	// checkSig but doesn't addOutput, so we use TerminalOutputs.
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(auctioneer)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	callOpts := &runar.CallOptions{
		TerminalOutputs: []runar.TerminalOutput{
			{ScriptHex: auctioneer.P2PKHScript(), Satoshis: 4500},
		},
	}
	txid, _, err := contract.Call(
		"close",
		[]interface{}{nil}, // sig placeholder — auto-signed by SDK
		provider, signer, callOpts,
	)
	if err != nil {
		t.Fatalf("close failed: %v", err)
	}
	t.Logf("close TX: %s", txid)
}

func TestAuction_Compile(t *testing.T) {
	artifact := getAuctionArtifact(t)
	if artifact.ContractName != "Auction" {
		t.Fatalf("expected contract name Auction, got %s", artifact.ContractName)
	}
	t.Logf("Auction compiled: %d bytes", len(artifact.Script)/2)
}

func TestAuction_Deploy(t *testing.T) {
	auctioneer := helpers.NewWallet()
	bidder := helpers.NewWallet()

	artifact := getAuctionArtifact(t)

	contract := runar.NewRunarContract(artifact, []interface{}{
		auctioneer.PubKeyHex(), bidder.PubKeyHex(), int64(1000), int64(1000000),
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, errF := helpers.FundWallet(funder, 1.0)
	if errF != nil {
		t.Fatalf("fund: %v", errF)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
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

	// deadline=0 allows close at any block time (locktime always satisfied).
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
