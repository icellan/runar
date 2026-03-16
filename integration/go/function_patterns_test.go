//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	runar "github.com/icellan/runar/packages/runar-go"
)

func deployFunctionPatterns(t *testing.T, owner *helpers.Wallet, initialBalance int64) (*runar.RunarContract, runar.Provider, runar.Signer) {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/function-patterns/FunctionPatterns.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("FunctionPatterns script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		int64(initialBalance),
	})

	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err = helpers.FundWallet(owner, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract, provider, signer
}

// buildFPSpendTx builds a raw spending transaction for a FunctionPatterns UTXO.
// It creates a continuation output with the new state (updated balance).
func buildFPSpendTx(t *testing.T, contract *runar.RunarContract, newBalance int64) *transaction.Transaction {
	t.Helper()

	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("contract has no current UTXO")
	}

	// Build the continuation locking script: code + OP_RETURN + new state
	lastOpReturn := runar.FindLastOpReturn(utxo.Script)
	if lastOpReturn == -1 {
		t.Fatalf("no OP_RETURN found in contract script")
	}
	codePart := utxo.Script[:lastOpReturn]

	// Serialize the new state: balance (bigint) -- only mutable field
	newState := runar.SerializeState(contract.Artifact.StateFields, map[string]interface{}{
		"balance": int64(newBalance),
	})
	continuationScript := codePart + "6a" + newState

	lockScript, _ := script.NewFromHex(utxo.Script)
	contScript, _ := script.NewFromHex(continuationScript)

	spendTx := transaction.NewTransaction()
	spendTx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       helpers.TxidToChainHash(utxo.Txid),
		SourceTxOutIndex: uint32(utxo.OutputIndex),
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      uint64(utxo.Satoshis),
		LockingScript: lockScript,
	})
	spendTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(utxo.Satoshis),
		LockingScript: contScript,
	})

	return spendTx
}

// sdkCallFunctionPatterns calls a FunctionPatterns method via the SDK.
func sdkCallFunctionPatterns(t *testing.T, contract *runar.RunarContract, provider runar.Provider, signer runar.Signer, methodName string, newBalance int64, extraArgs []interface{}) {
	t.Helper()

	// Build args: sig (auto) + extraArgs
	args := []interface{}{nil} // Sig = auto
	args = append(args, extraArgs...)

	txid, _, err := contract.Call(methodName, args, provider, signer, nil)
	if err != nil {
		t.Fatalf("%s (balance->%d): %v", methodName, newBalance, err)
	}
	t.Logf("balance->%d TX: %s", newBalance, txid)
}

func TestFunctionPatterns_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/function-patterns/FunctionPatterns.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "FunctionPatterns" {
		t.Fatalf("expected contract name FunctionPatterns, got %s", artifact.ContractName)
	}
	t.Logf("FunctionPatterns compiled: %d bytes", len(artifact.Script)/2)
}

func TestFunctionPatterns_Deploy(t *testing.T) {
	owner := helpers.NewWallet()
	contract, _, _ := deployFunctionPatterns(t, owner, 100)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with balance=100")
}

func TestFunctionPatterns_DeployZeroBalance(t *testing.T) {
	owner := helpers.NewWallet()
	contract, _, _ := deployFunctionPatterns(t, owner, 0)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with balance=0")
}

func TestFunctionPatterns_DeployLargeBalance(t *testing.T) {
	owner := helpers.NewWallet()
	contract, _, _ := deployFunctionPatterns(t, owner, 999999999)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with large balance=999999999")
}

func TestFunctionPatterns_DistinctTxids(t *testing.T) {
	owner1 := helpers.NewWallet()
	owner2 := helpers.NewWallet()

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/function-patterns/FunctionPatterns.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Deploy first instance
	contract1 := runar.NewRunarContract(artifact, []interface{}{owner1.PubKeyHex(), int64(100)})
	funder1 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder1.Address, "", false)
	_, err = helpers.FundWallet(funder1, 1.0)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	provider1 := helpers.NewRPCProvider()
	signer1, _ := helpers.SDKSignerFromWallet(funder1)
	txid1, _, err := contract1.Deploy(provider1, signer1, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy1: %v", err)
	}

	// Deploy second instance
	contract2 := runar.NewRunarContract(artifact, []interface{}{owner2.PubKeyHex(), int64(200)})
	funder2 := helpers.NewWallet()
	helpers.RPCCall("importaddress", funder2.Address, "", false)
	_, err = helpers.FundWallet(funder2, 1.0)
	if err != nil {
		t.Fatalf("fund2: %v", err)
	}
	provider2 := helpers.NewRPCProvider()
	signer2, _ := helpers.SDKSignerFromWallet(funder2)
	txid2, _, err := contract2.Deploy(provider2, signer2, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy2: %v", err)
	}

	if txid1 == txid2 {
		t.Fatalf("expected distinct txids, got same: %s", txid1)
	}
	t.Logf("distinct txids: %s vs %s", txid1, txid2)
}

func TestFunctionPatterns_Deposit(t *testing.T) {
	owner := helpers.NewWallet()
	contract, provider, signer := deployFunctionPatterns(t, owner, 100)

	// deposit(sig, amount=50) -> balance = 150
	sdkCallFunctionPatterns(t, contract, provider, signer, "deposit", 150, []interface{}{int64(50)})
}

func TestFunctionPatterns_DepositThenWithdraw(t *testing.T) {
	owner := helpers.NewWallet()
	contract, provider, signer := deployFunctionPatterns(t, owner, 1000)

	// deposit 500 -> 1500
	sdkCallFunctionPatterns(t, contract, provider, signer, "deposit", 1500, []interface{}{int64(500)})

	// withdraw(sig, amount=200, feeBps=100) -> fee=2, total=202, balance=1298
	sdkCallFunctionPatterns(t, contract, provider, signer, "withdraw", 1298, []interface{}{int64(200), int64(100)})
	t.Logf("chain: 1000->1500->1298 succeeded")
}

func TestFunctionPatterns_WrongOwner_Rejected(t *testing.T) {
	owner := helpers.NewWallet()
	attacker := helpers.NewWallet()
	contract, _, _ := deployFunctionPatterns(t, owner, 100)

	// Attacker tries to deposit -- requireOwner(sig) should fail
	spendTx := buildFPSpendTx(t, contract, 200)

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

	// Unlocking: <opPushTxSig> <sig> <amount> <txPreimage> <methodIndex>
	unlockHex := helpers.EncodePushBytes(opPushTxSigBytes) +
		helpers.EncodePushBytes(sigBytes) +
		helpers.EncodePushInt(100) +
		helpers.EncodePushBytes(preimageBytes) +
		helpers.EncodeMethodIndex(0)

	unlockScript, _ := script.NewFromHex(unlockHex)
	spendTx.Inputs[0].UnlockingScript = unlockScript

	helpers.AssertTxRejected(t, spendTx.Hex())
}
