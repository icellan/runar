//go:build integration

package integration

import (
	"encoding/hex"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

var ftArtifact *runar.RunarArtifact
var ftOnce sync.Once

func getFTArtifact(t *testing.T) *runar.RunarArtifact {
	ftOnce.Do(func() {
		var err error
		ftArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/token-ft/FungibleTokenExample.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile FungibleToken: %v", err)
		}
	})
	return ftArtifact
}

// deployFungibleToken compiles and deploys a FungibleToken contract using the SDK,
// returning the contract, provider, and signer. The owner wallet is funded directly
// and the returned signer corresponds to the owner key, so Call("send", ...) works
// with checkSig.
func deployFungibleToken(t *testing.T, owner *helpers.Wallet, initialBalance int64, provider *helpers.BatchRPCProvider) (*runar.RunarContract, *helpers.BatchRPCProvider, runar.Signer) {
	t.Helper()

	tokenIdHex := hex.EncodeToString([]byte("TEST-TOKEN-001"))

	artifact := getFTArtifact(t)
	t.Logf("FungibleToken script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		int64(initialBalance),
		int64(0),
		tokenIdHex,
	})

	// Fund the owner wallet directly so the signer matches the contract owner
	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err := helpers.FundWallet(owner, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	return contract, provider, signer
}

func TestFungibleToken_Compile(t *testing.T) {
	artifact := getFTArtifact(t)
	if artifact.ContractName != "FungibleToken" {
		t.Fatalf("expected contract name FungibleToken, got %s", artifact.ContractName)
	}
	t.Logf("FungibleToken compiled: %d bytes", len(artifact.Script)/2)
}

func TestFungibleToken_Deploy(t *testing.T) {
	owner := helpers.NewWallet()
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	contract, _, _ := deployFungibleToken(t, owner, 1000, provider)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with balance=1000")
}

func TestFungibleToken_DeployZeroBalance(t *testing.T) {
	owner := helpers.NewWallet()
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	contract, _, _ := deployFungibleToken(t, owner, 0, provider)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with balance=0")
}

func TestFungibleToken_DeployLargeBalance(t *testing.T) {
	owner := helpers.NewWallet()
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	contract, _, _ := deployFungibleToken(t, owner, 99999999999, provider)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with large balance=99999999999")
}

func TestFungibleToken_Send(t *testing.T) {
	// FungibleToken: StatefulSmartContract with addOutput
	// send(sig, to, outputSatoshis) -- transfers entire balance to new owner
	owner := helpers.NewWallet()
	receiver := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	// Deploy using SDK (owner wallet is funded, signer matches owner key)
	contract, _, ownerSigner := deployFungibleToken(t, owner, initialBalance, provider)

	// Call send via SDK: sig is nil (auto-computed), to=receiver, outputSatoshis
	// send uses addOutput, so we need Outputs (not NewState)
	txid, _, err := contract.Call("send",
		[]interface{}{nil, receiver.PubKeyHex(), outputSatoshis},
		provider, ownerSigner,
		&runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": receiver.PubKeyHex(), "balance": initialBalance, "mergeBalance": int64(0)}},
			},
		})
	if err != nil {
		t.Fatalf("send call: %v", err)
	}
	t.Logf("send TX: %s", txid)
}

func TestFungibleToken_WrongOwner_Rejected(t *testing.T) {
	owner := helpers.NewWallet()
	attacker := helpers.NewWallet()
	receiver := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	// Deploy with owner's key
	contract, _, _ := deployFungibleToken(t, owner, initialBalance, provider)

	// Fund the attacker wallet and create a signer from it
	helpers.RPCCall("importaddress", attacker.Address, "", false)
	_, err := helpers.FundWallet(attacker, 1.0)
	if err != nil {
		t.Fatalf("fund attacker: %v", err)
	}
	attackerSigner, err := helpers.SDKSignerFromWallet(attacker)
	if err != nil {
		t.Fatalf("attacker signer: %v", err)
	}

	// Call send with attacker's signer -- checkSig should fail because
	// the attacker's key doesn't match the contract owner
	_, _, err = contract.Call("send",
		[]interface{}{nil, receiver.PubKeyHex(), outputSatoshis},
		provider, attackerSigner,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": receiver.PubKeyHex(), "balance": initialBalance, "mergeBalance": int64(0)},
		})
	if err == nil {
		t.Fatalf("expected send with wrong owner to be rejected, but it succeeded")
	}
	t.Logf("send correctly rejected with wrong owner: %v", err)
}

func TestFungibleToken_Transfer(t *testing.T) {
	// Transfer splits 1 UTXO into 2 outputs:
	// output 0 → recipient gets `amount`, output 1 → sender keeps remainder
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	amount := int64(300)
	remainder := initialBalance - amount
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, aliceSigner := deployFungibleToken(t, alice, initialBalance, provider)

	// SDK Call with multi-output: transfer method (index 0)
	// transfer(sig, to, amount, outputSatoshis)
	txid, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), amount, outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": amount, "mergeBalance": int64(0)}},
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": remainder, "mergeBalance": int64(0)}},
			},
		})
	if err != nil {
		t.Fatalf("transfer call: %v", err)
	}
	t.Logf("transfer TX: %s", txid)
}

func TestFungibleToken_Merge(t *testing.T) {
	// Merge consolidates 2 UTXOs into 1 output (same owner)
	// Uses position-dependent balance slots for anti-inflation security
	alice := helpers.NewWallet()
	balance1 := int64(400)
	balance2 := int64(600)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract1, _, aliceSigner := deployFungibleToken(t, alice, balance1, provider)
	contract2, _, _ := deployFungibleToken(t, alice, balance2, provider)

	utxo2 := contract2.GetCurrentUtxo()
	if utxo2 == nil {
		t.Fatalf("missing UTXO after deploy for contract2")
	}

	// merge(sig, otherBalance, allPrevouts, outputSatoshis)
	// allPrevouts is nil (auto-computed by SDK from transaction inputs)
	txid, _, err := contract1.Call("merge",
		[]interface{}{nil, balance2, nil, outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": balance1, "mergeBalance": balance2}},
			},
			AdditionalContractInputs: []*runar.UTXO{
				{Txid: utxo2.Txid, OutputIndex: utxo2.OutputIndex, Satoshis: utxo2.Satoshis, Script: utxo2.Script},
			},
			AdditionalContractInputArgs: [][]interface{}{
				{nil, balance1, nil, outputSatoshis},
			},
		})
	if err != nil {
		t.Fatalf("merge call: %v", err)
	}
	t.Logf("merge TX: %s", txid)
}

func TestFungibleToken_MergeInflatedOtherBalance(t *testing.T) {
	// Attacker lies about otherBalance. With secure merge, each input writes its
	// own verified balance to a position-dependent slot. hashOutputs forces both
	// inputs to produce identical outputs, so lying causes a mismatch.
	alice := helpers.NewWallet()
	balance1 := int64(400)
	balance2 := int64(600)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract1, _, aliceSigner := deployFungibleToken(t, alice, balance1, provider)
	contract2, _, _ := deployFungibleToken(t, alice, balance2, provider)

	utxo2 := contract2.GetCurrentUtxo()
	if utxo2 == nil {
		t.Fatalf("missing UTXO after deploy for contract2")
	}

	// Attacker: input 0 claims otherBalance=1600, input 1 claims otherBalance=1400
	// Output from input 0: (400, 1600), from input 1: (1400, 600) → mismatch
	_, _, err := contract1.Call("merge",
		[]interface{}{nil, int64(1600), nil, outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": balance1, "mergeBalance": int64(1600)}},
			},
			AdditionalContractInputs: []*runar.UTXO{
				{Txid: utxo2.Txid, OutputIndex: utxo2.OutputIndex, Satoshis: utxo2.Satoshis, Script: utxo2.Script},
			},
			AdditionalContractInputArgs: [][]interface{}{
				{nil, int64(1400), nil, outputSatoshis},
			},
		})
	if err == nil {
		t.Fatalf("expected merge with inflated otherBalance to be rejected, but it succeeded")
	}
	t.Logf("merge correctly rejected with inflated otherBalance: %v", err)
}

func TestFungibleToken_MergeNegativeOtherBalance(t *testing.T) {
	// Negative otherBalance fails assert(otherBalance >= 0)
	alice := helpers.NewWallet()
	balance1 := int64(400)
	balance2 := int64(600)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract1, _, aliceSigner := deployFungibleToken(t, alice, balance1, provider)
	contract2, _, _ := deployFungibleToken(t, alice, balance2, provider)

	utxo2 := contract2.GetCurrentUtxo()
	if utxo2 == nil {
		t.Fatalf("missing UTXO after deploy for contract2")
	}

	_, _, err := contract1.Call("merge",
		[]interface{}{nil, int64(100), nil, outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": balance1, "mergeBalance": int64(100)}},
			},
			AdditionalContractInputs: []*runar.UTXO{
				{Txid: utxo2.Txid, OutputIndex: utxo2.OutputIndex, Satoshis: utxo2.Satoshis, Script: utxo2.Script},
			},
			AdditionalContractInputArgs: [][]interface{}{
				{nil, int64(-1), nil, outputSatoshis},
			},
		})
	if err == nil {
		t.Fatalf("expected merge with negative otherBalance to be rejected, but it succeeded")
	}
	t.Logf("merge correctly rejected with negative otherBalance: %v", err)
}

func TestFungibleToken_MergeZeroBalance(t *testing.T) {
	// Edge case: merge with one zero-balance UTXO. Should succeed.
	alice := helpers.NewWallet()
	balance1 := int64(0)
	balance2 := int64(500)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract1, _, aliceSigner := deployFungibleToken(t, alice, balance1, provider)
	contract2, _, _ := deployFungibleToken(t, alice, balance2, provider)

	utxo2 := contract2.GetCurrentUtxo()
	if utxo2 == nil {
		t.Fatalf("missing UTXO after deploy for contract2")
	}

	txid, _, err := contract1.Call("merge",
		[]interface{}{nil, balance2, nil, outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": balance1, "mergeBalance": balance2}},
			},
			AdditionalContractInputs: []*runar.UTXO{
				{Txid: utxo2.Txid, OutputIndex: utxo2.OutputIndex, Satoshis: utxo2.Satoshis, Script: utxo2.Script},
			},
			AdditionalContractInputArgs: [][]interface{}{
				{nil, balance1, nil, outputSatoshis},
			},
		})
	if err != nil {
		t.Fatalf("merge with zero balance: %v", err)
	}
	t.Logf("merge TX: %s", txid)
}

func TestFungibleToken_MergeWrongSigner(t *testing.T) {
	// Different signer tries to merge. Should fail checkSig.
	alice := helpers.NewWallet()
	attacker := helpers.NewWallet()
	balance1 := int64(400)
	balance2 := int64(600)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract1, _, _ := deployFungibleToken(t, alice, balance1, provider)
	contract2, _, _ := deployFungibleToken(t, alice, balance2, provider)

	utxo2 := contract2.GetCurrentUtxo()
	if utxo2 == nil {
		t.Fatalf("missing UTXO after deploy for contract2")
	}

	// Fund attacker wallet and create attacker signer
	helpers.RPCCall("importaddress", attacker.Address, "", false)
	_, err := helpers.FundWallet(attacker, 1.0)
	if err != nil {
		t.Fatalf("fund attacker: %v", err)
	}
	attackerSigner, err := helpers.SDKSignerFromWallet(attacker)
	if err != nil {
		t.Fatalf("attacker signer: %v", err)
	}

	_, _, err = contract1.Call("merge",
		[]interface{}{nil, balance2, nil, outputSatoshis},
		provider, attackerSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": balance1, "mergeBalance": balance2}},
			},
			AdditionalContractInputs: []*runar.UTXO{
				{Txid: utxo2.Txid, OutputIndex: utxo2.OutputIndex, Satoshis: utxo2.Satoshis, Script: utxo2.Script},
			},
			AdditionalContractInputArgs: [][]interface{}{
				{nil, balance1, nil, outputSatoshis},
			},
		})
	if err == nil {
		t.Fatalf("expected merge with wrong signer to be rejected, but it succeeded")
	}
	t.Logf("merge correctly rejected with wrong signer: %v", err)
}

func TestFungibleToken_TransferExactBalance(t *testing.T) {
	// Transfer the entire balance to recipient. Should produce only 1 output (no change).
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, aliceSigner := deployFungibleToken(t, alice, initialBalance, provider)

	txid, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), initialBalance, outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": initialBalance, "mergeBalance": int64(0)}},
			},
		})
	if err != nil {
		t.Fatalf("transfer exact balance: %v", err)
	}
	t.Logf("transfer exact balance (1 output, no change) accepted: %s", txid)
}

func TestFungibleToken_TransferInflatedBalance(t *testing.T) {
	// Attacker tries to inflate balance: claims outputs total more than input balance.
	// hashOutputs mismatch should reject this on-chain.
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, aliceSigner := deployFungibleToken(t, alice, initialBalance, provider)

	// Attacker claims bob gets 800 and alice keeps 500 = 1300 total (inflated from 1000)
	_, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), int64(800), outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": int64(800), "mergeBalance": int64(0)}},
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": int64(500), "mergeBalance": int64(0)}},
			},
		})
	if err == nil {
		t.Fatalf("expected transfer with inflated balance to be rejected, but it succeeded")
	}
	t.Logf("transfer correctly rejected inflated balance: %v", err)
}

func TestFungibleToken_TransferDeflatedBalance(t *testing.T) {
	// Attacker tries to steal by deflating: claims outputs total less than input.
	// The script computes totalBalance - amount for change, so mismatched outputs
	// will cause hashOutputs failure.
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, aliceSigner := deployFungibleToken(t, alice, initialBalance, provider)

	// Attacker claims bob gets 300 and alice keeps 200 = 500 total (deflated from 1000)
	_, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), int64(300), outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": int64(300), "mergeBalance": int64(0)}},
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": int64(200), "mergeBalance": int64(0)}},
			},
		})
	if err == nil {
		t.Fatalf("expected transfer with deflated balance to be rejected, but it succeeded")
	}
	t.Logf("transfer correctly rejected deflated balance: %v", err)
}

func TestFungibleToken_TransferZeroAmountRejected(t *testing.T) {
	// Transfer of zero amount should fail the assert(amount > 0) check.
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, aliceSigner := deployFungibleToken(t, alice, initialBalance, provider)

	_, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), int64(0), outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": int64(0), "mergeBalance": int64(0)}},
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": initialBalance, "mergeBalance": int64(0)}},
			},
		})
	if err == nil {
		t.Fatalf("expected transfer of zero amount to be rejected, but it succeeded")
	}
	t.Logf("transfer correctly rejected zero amount: %v", err)
}

func TestFungibleToken_TransferExceedsBalanceRejected(t *testing.T) {
	// Transfer exceeding balance should fail the assert(amount <= totalBalance) check.
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, aliceSigner := deployFungibleToken(t, alice, initialBalance, provider)

	_, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), int64(2000), outputSatoshis},
		provider, aliceSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": int64(2000), "mergeBalance": int64(0)}},
			},
		})
	if err == nil {
		t.Fatalf("expected transfer exceeding balance to be rejected, but it succeeded")
	}
	t.Logf("transfer correctly rejected amount exceeding balance: %v", err)
}

func TestFungibleToken_TransferWrongSigner(t *testing.T) {
	// Different signer tries to transfer. Should fail checkSig.
	alice := helpers.NewWallet()
	attacker := helpers.NewWallet()
	bob := helpers.NewWallet()
	initialBalance := int64(1000)
	amount := int64(300)
	remainder := initialBalance - amount
	outputSatoshis := int64(4500)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, _ := deployFungibleToken(t, alice, initialBalance, provider)

	// Fund attacker wallet and create attacker signer
	helpers.RPCCall("importaddress", attacker.Address, "", false)
	_, err := helpers.FundWallet(attacker, 1.0)
	if err != nil {
		t.Fatalf("fund attacker: %v", err)
	}
	attackerSigner, err := helpers.SDKSignerFromWallet(attacker)
	if err != nil {
		t.Fatalf("attacker signer: %v", err)
	}

	_, _, err = contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), amount, outputSatoshis},
		provider, attackerSigner, &runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": amount}},
				{Satoshis: outputSatoshis, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": remainder}},
			},
		})
	if err == nil {
		t.Fatalf("expected transfer with wrong signer to be rejected, but it succeeded")
	}
	t.Logf("transfer correctly rejected with wrong signer: %v", err)
}
