//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/bsv-blockchain/go-sdk/script"
)

func TestNFT_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "SimpleNFT" {
		t.Fatalf("expected contract name SimpleNFT, got %s", artifact.ContractName)
	}
	t.Logf("SimpleNFT compiled: %d bytes", len(artifact.Script)/2)
}

func TestNFT_Deploy(t *testing.T) {
	owner := helpers.NewWallet()
	tokenIdHex := hex.EncodeToString([]byte("NFT-DEPLOY-001"))
	metadataHex := hex.EncodeToString([]byte("Deploy test"))

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(), tokenIdHex, metadataHex,
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 0.01)
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

func TestNFT_DeployDifferentOwners(t *testing.T) {
	owner1 := helpers.NewWallet()
	owner2 := helpers.NewWallet()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	tokenIdHex := hex.EncodeToString([]byte("NFT-DIFF-001"))
	metadataHex := hex.EncodeToString([]byte("Diff owners test"))

	// Deploy first NFT
	contract1 := runar.NewRunarContract(artifact, []interface{}{
		owner1.PubKeyHex(), tokenIdHex, metadataHex,
	})
	funder1 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder1.Address, "", false)
	_, err = helpers.FundWallet(funder1, 0.01)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	provider1 := helpers.NewRPCProvider()
	signer1, _ := helpers.SDKSignerFromWallet(funder1)
	txid1, _, err := contract1.Deploy(provider1, signer1, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy1: %v", err)
	}

	// Deploy second NFT with different owner
	contract2 := runar.NewRunarContract(artifact, []interface{}{
		owner2.PubKeyHex(), tokenIdHex, metadataHex,
	})
	funder2 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder2.Address, "", false)
	_, err = helpers.FundWallet(funder2, 0.01)
	if err != nil {
		t.Fatalf("fund2: %v", err)
	}
	provider2 := helpers.NewRPCProvider()
	signer2, _ := helpers.SDKSignerFromWallet(funder2)
	txid2, _, err := contract2.Deploy(provider2, signer2, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy2: %v", err)
	}

	if txid1 == txid2 {
		t.Fatalf("expected different txids, got same: %s", txid1)
	}
	t.Logf("NFT1: %s, NFT2: %s", txid1, txid2)
}

func TestNFT_DeployLongMetadata(t *testing.T) {
	owner := helpers.NewWallet()
	tokenIdHex := hex.EncodeToString([]byte("NFT-LONG-001"))
	// 256-byte metadata
	longMeta := make([]byte, 256)
	for i := range longMeta {
		longMeta[i] = byte(i % 256)
	}
	metadataHex := hex.EncodeToString(longMeta)

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(), tokenIdHex, metadataHex,
	})

	funder := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder.Address, "", false)
	_, err = helpers.FundWallet(funder, 0.01)
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
	t.Logf("deployed with 256-byte metadata: %s", txid)
}

func TestNFT_Transfer(t *testing.T) {
	// SimpleNFT: StatefulSmartContract with addOutput
	// transfer(sig, newOwner, outputSatoshis) — transfers NFT to new owner via SDK
	owner := helpers.NewWallet()
	newOwner := helpers.NewWallet()
	tokenIdHex := hex.EncodeToString([]byte("NFT-001"))
	metadataHex := hex.EncodeToString([]byte("My First NFT"))

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("SimpleNFT script: %d bytes", len(artifact.Script)/2)
	if artifact.CodeSeparatorIndex != nil {
		t.Logf("codeSepIdx: %d", *artifact.CodeSeparatorIndex)
	}
	t.Logf("codeSepIndices: %v", artifact.CodeSeparatorIndices)
	t.Logf("constructorSlots: %v", artifact.ConstructorSlots)

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		tokenIdHex,
		metadataHex,
	})

	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err = helpers.FundWallet(owner, 0.01)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	// Transfer via SDK Call with multi-output
	outputSatoshis := int64(4500)
	callOpts := &runar.CallOptions{
		Outputs: []runar.OutputSpec{
			{
				Satoshis: outputSatoshis,
				State: map[string]interface{}{
					"owner":    newOwner.PubKeyHex(),
					"tokenId":  tokenIdHex,
					"metadata": metadataHex,
				},
			},
		},
	}
	txid, _, err := contract.Call(
		"transfer",
		[]interface{}{nil, newOwner.PubKeyHex(), outputSatoshis},
		provider, signer, callOpts,
	)
	if err != nil {
		t.Fatalf("transfer failed: %v", err)
	}
	t.Logf("transfer TX: %s", txid)
}

func TestNFT_Burn(t *testing.T) {
	// burn(sig) — destroys the NFT. No continuation output, just pays to a P2PKH.
	owner := helpers.NewWallet()
	tokenIdHex := hex.EncodeToString([]byte("NFT-BURN-001"))
	metadataHex := hex.EncodeToString([]byte("Burnable NFT"))

	// Compile using SDK artifact path
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Create contract with constructor args: owner, tokenId, metadata
	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		tokenIdHex,
		metadataHex,
	})

	// Fund wallet and deploy via SDK
	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err = helpers.FundWallet(owner, 0.01)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	// burn(sig) via SDK terminal call — method 1. The script verifies
	// checkSig but doesn't addOutput, so we use TerminalOutputs to
	// specify the exact output (P2PKH to owner).
	callOpts := &runar.CallOptions{
		TerminalOutputs: []runar.TerminalOutput{
			{ScriptHex: owner.P2PKHScript(), Satoshis: 4500},
		},
	}
	txid, _, err := contract.Call(
		"burn",
		[]interface{}{nil}, // sig placeholder — auto-signed by SDK
		provider, signer, callOpts,
	)
	if err != nil {
		t.Fatalf("burn failed: %v", err)
	}
	t.Logf("burn TX: %s", txid)
}

func TestNFT_WrongOwner_Rejected(t *testing.T) {
	owner := helpers.NewWallet()
	attacker := helpers.NewWallet()
	tokenIdHex := hex.EncodeToString([]byte("NFT-STEAL-001"))
	metadataHex := hex.EncodeToString([]byte("Steal attempt"))

	// Compile using SDK artifact path
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/token-nft/NFTExample.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Create contract with constructor args: owner, tokenId, metadata
	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		tokenIdHex,
		metadataHex,
	})

	// Fund the owner wallet and deploy via SDK
	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err = helpers.FundWallet(owner, 0.01)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	// --- Raw spending path: attacker tries to burn ---

	contractUTXO := contract.GetCurrentUtxo()
	if contractUTXO == nil {
		t.Fatalf("no current UTXO after deploy")
	}

	// Attacker tries to burn — should fail checkSig
	spendTx, err := helpers.BuildSpendTx(
		&helpers.UTXO{
			Txid:     contractUTXO.Txid,
			Vout:     contractUTXO.OutputIndex,
			Satoshis: contractUTXO.Satoshis,
			Script:   contractUTXO.Script,
		},
		attacker.P2PKHScript(),
		4500,
	)
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
		helpers.EncodeMethodIndex(1)

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	helpers.AssertTxRejected(t, spendTx.Hex())
}
