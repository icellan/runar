//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	"github.com/bsv-blockchain/go-sdk/script"

	runar "github.com/icellan/runar/packages/runar-go"
)

func deployCovenantVault(t *testing.T, owner, recipient *helpers.Wallet, minAmount int64) *runar.RunarContract {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/covenant-vault/CovenantVault.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("CovenantVault script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		recipient.PubKeyHashHex(),
		int64(minAmount),
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

	return contract
}

func TestCovenantVault_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/covenant-vault/CovenantVault.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "CovenantVault" {
		t.Fatalf("expected contract name CovenantVault, got %s", artifact.ContractName)
	}
	t.Logf("CovenantVault compiled: %d bytes", len(artifact.Script)/2)
}

func TestCovenantVault_Deploy(t *testing.T) {
	owner := helpers.NewWallet()
	recipient := helpers.NewWallet()
	contract := deployCovenantVault(t, owner, recipient, 1000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with minAmount=1000")
}

func TestCovenantVault_DeployZeroMinAmount(t *testing.T) {
	owner := helpers.NewWallet()
	recipient := helpers.NewWallet()
	contract := deployCovenantVault(t, owner, recipient, 0)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with minAmount=0")
}

func TestCovenantVault_DeployLargeMinAmount(t *testing.T) {
	owner := helpers.NewWallet()
	recipient := helpers.NewWallet()
	contract := deployCovenantVault(t, owner, recipient, 100000000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with minAmount=100000000 (1 BTC)")
}

func TestCovenantVault_DeploySameKey(t *testing.T) {
	wallet := helpers.NewWallet()
	contract := deployCovenantVault(t, wallet, wallet, 1000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with same key as owner and recipient")
}

func TestCovenantVault_ValidSpend(t *testing.T) {
	owner := helpers.NewWallet()
	recipient := helpers.NewWallet()
	minAmount := int64(1000)

	contract := deployCovenantVault(t, owner, recipient, minAmount)

	// Get UTXO from SDK contract, convert for raw spending
	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	// Build spend TX with the EXACT output the covenant expects:
	// A P2PKH output to the recipient for minAmount satoshis.
	// The covenant verifies hash256(expectedOutput) == extractOutputHash(txPreimage),
	// where expectedOutput = num2bin(minAmount, 8) || "1976a914" || recipient || "88ac"
	recipientScript := recipient.P2PKHScript()
	spendTx, err := helpers.BuildSpendTx(utxo, recipientScript, minAmount)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}

	// Sign with owner's key
	sigHex, err := helpers.SignInput(spendTx, 0, owner.PrivKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	// OP_PUSH_TX for checkPreimage
	opPushTxSigHex, preimageHex, err := helpers.SignOpPushTx(spendTx, 0)
	if err != nil {
		t.Fatalf("op_push_tx: %v", err)
	}
	opPushTxSigBytes, _ := hex.DecodeString(opPushTxSigHex)
	preimageBytes, _ := hex.DecodeString(preimageHex)

	// spend(sig: Sig, txPreimage: SigHashPreimage)
	// Compiler inserts implicit _opPushTxSig before declared params.
	// Unlocking script order: <opPushTxSig> <sig> <txPreimage>
	unlockHex := helpers.EncodePushBytes(opPushTxSigBytes) +
		helpers.EncodePushBytes(sigBytes) +
		helpers.EncodePushBytes(preimageBytes)

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	txid := helpers.AssertTxAccepted(t, spendTx.Hex())
	helpers.AssertTxInBlock(t, txid)
}

// TestCovenantVault_WrongOutput_Rejected verifies the covenant rejects a transaction
// whose output doesn't match the expected P2PKH to the registered recipient.
func TestCovenantVault_WrongOutput_Rejected(t *testing.T) {
	owner := helpers.NewWallet()
	recipient := helpers.NewWallet()
	minAmount := int64(1000)

	contract := deployCovenantVault(t, owner, recipient, minAmount)

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())

	// Build TX with wrong output: send to OWNER instead of RECIPIENT.
	// The covenant expects output to recipient — this should fail the
	// hash256(expectedOutput) == extractOutputHash(txPreimage) check.
	wrongScript := owner.P2PKHScript()
	spendTx, err := helpers.BuildSpendTx(utxo, wrongScript, minAmount)
	if err != nil {
		t.Fatalf("build spend: %v", err)
	}

	sigHex, err := helpers.SignInput(spendTx, 0, owner.PrivKey)
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

	// Unlocking script order: <opPushTxSig> <sig> <txPreimage>
	unlockHex := helpers.EncodePushBytes(opPushTxSigBytes) +
		helpers.EncodePushBytes(sigBytes) +
		helpers.EncodePushBytes(preimageBytes)

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	helpers.AssertTxRejected(t, spendTx.Hex())
}
