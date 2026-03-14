//go:build integration

package integration

import (
	"encoding/hex"
	"strings"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// deployInductiveToken compiles and deploys an InductiveToken contract using the SDK,
// returning the contract, provider, and signer. The owner wallet is funded directly
// and the returned signer corresponds to the owner key.
func deployInductiveToken(t *testing.T, owner *helpers.Wallet, initialBalance int64) (*runar.RunarContract, runar.Provider, runar.Signer) {
	t.Helper()

	tokenIdHex := hex.EncodeToString([]byte("TEST-INDUCTIVE-TOKEN"))
	zeroSentinel := strings.Repeat("00", 36)  // 36 zero bytes for _genesisOutpoint
	zeroProof := strings.Repeat("00", 256)     // 256 zero bytes for _proof

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/inductive-token/InductiveToken.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("InductiveToken script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{
		owner.PubKeyHex(),
		initialBalance,
		tokenIdHex,
		zeroSentinel,
		zeroProof,
	})

	// Fund the owner wallet directly so the signer matches the contract owner
	helpers.RPCCall("importaddress", owner.Address, "", false)
	_, err = helpers.FundWallet(owner, 2.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(owner)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// Inductive scripts are ~75KB, deploy with high satoshis
	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	return contract, provider, signer
}

func TestInductiveToken_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/inductive-token/InductiveToken.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "InductiveToken" {
		t.Fatalf("expected contract name InductiveToken, got %s", artifact.ContractName)
	}
	t.Logf("InductiveToken compiled: %d bytes", len(artifact.Script)/2)
}

func TestInductiveToken_Deploy(t *testing.T) {
	owner := helpers.NewWallet()
	contract, _, _ := deployInductiveToken(t, owner, 1000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed with balance=1000")
}

func TestInductiveToken_SendChain(t *testing.T) {
	// Deploy + 3 sends: genesis (Tx1) + 2 non-genesis (Tx2, Tx3)
	// Tests inductive lineage verification across chain depth 3.
	owner := helpers.NewWallet()
	contract, provider, signer := deployInductiveToken(t, owner, 1000)

	// Tx1: First spend (genesis detection branch)
	// _genesisOutpoint == zero sentinel -> genesis branch sets _genesisOutpoint
	txid1, _, err := contract.Call("send",
		[]interface{}{nil, owner.PubKeyHex(), int64(1)},
		provider, signer,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": owner.PubKeyHex()},
			Satoshis: 1,
		})
	if err != nil {
		t.Fatalf("send Tx1 (genesis): %v", err)
	}
	helpers.AssertTxInBlock(t, txid1)
	t.Logf("Tx1 (genesis): %s", txid1)

	// Tx2: Second spend (non-genesis — verifies parent via SHA-256 compress)
	txid2, _, err := contract.Call("send",
		[]interface{}{nil, owner.PubKeyHex(), int64(1)},
		provider, signer,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": owner.PubKeyHex()},
			Satoshis: 1,
		})
	if err != nil {
		t.Fatalf("send Tx2 (non-genesis): %v", err)
	}
	helpers.AssertTxInBlock(t, txid2)
	t.Logf("Tx2 (non-genesis): %s", txid2)

	// Tx3: Third spend (depth 3 — full lineage chain)
	txid3, _, err := contract.Call("send",
		[]interface{}{nil, owner.PubKeyHex(), int64(1)},
		provider, signer,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": owner.PubKeyHex()},
			Satoshis: 1,
		})
	if err != nil {
		t.Fatalf("send Tx3 (depth 3): %v", err)
	}
	helpers.AssertTxInBlock(t, txid3)
	t.Logf("Tx3 (depth 3): %s", txid3)
	t.Logf("chain: deploy -> Tx1 -> Tx2 -> Tx3 succeeded")
}

func TestInductiveToken_Transfer(t *testing.T) {
	// Deploy + send (genesis) + transfer (multi-output split)
	// Tests that multi-output splitting preserves inductive lineage.
	alice := helpers.NewWallet()
	bob := helpers.NewWallet()
	contract, provider, aliceSigner := deployInductiveToken(t, alice, 1000)

	// Tx1: genesis send (to self)
	txid1, _, err := contract.Call("send",
		[]interface{}{nil, alice.PubKeyHex(), int64(1)},
		provider, aliceSigner,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": alice.PubKeyHex()},
			Satoshis: 1,
		})
	if err != nil {
		t.Fatalf("send Tx1 (genesis): %v", err)
	}
	helpers.AssertTxInBlock(t, txid1)
	t.Logf("Tx1 (genesis): %s", txid1)

	// Tx2: transfer — 300 to bob, 700 remains with alice
	txid2, _, err := contract.Call("transfer",
		[]interface{}{nil, bob.PubKeyHex(), int64(300), int64(1)},
		provider, aliceSigner,
		&runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: 1, State: map[string]interface{}{"owner": bob.PubKeyHex(), "balance": int64(300)}},
				{Satoshis: 1, State: map[string]interface{}{"owner": alice.PubKeyHex(), "balance": int64(700)}},
			},
			ContinuationOutputIndex: 1,
		})
	if err != nil {
		t.Fatalf("transfer Tx2 (split): %v", err)
	}
	helpers.AssertTxInBlock(t, txid2)
	t.Logf("Tx2 (transfer split 300/700): %s", txid2)
}

func TestInductiveToken_WrongSigner_Rejected(t *testing.T) {
	// Wrong key should fail checkSig even with correct lineage.
	owner := helpers.NewWallet()
	attacker := helpers.NewWallet()
	contract, provider, ownerSigner := deployInductiveToken(t, owner, 1000)

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

	// Tx1: genesis (legitimate owner signs)
	txid1, _, err := contract.Call("send",
		[]interface{}{nil, owner.PubKeyHex(), int64(1)},
		provider, ownerSigner,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": owner.PubKeyHex()},
			Satoshis: 1,
		})
	if err != nil {
		t.Fatalf("send Tx1 (genesis): %v", err)
	}
	helpers.AssertTxInBlock(t, txid1)

	// Tx2: attacker tries to spend with wrong key -> checkSig fails
	_, _, err = contract.Call("send",
		[]interface{}{nil, owner.PubKeyHex(), int64(1)},
		provider, attackerSigner,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": owner.PubKeyHex()},
			Satoshis: 1,
		})
	if err == nil {
		t.Fatalf("expected send with wrong signer to be rejected, but it succeeded")
	}
	t.Logf("send correctly rejected with wrong signer: %v", err)
}

func TestInductiveToken_Overspend_Rejected(t *testing.T) {
	// Transfer amount > balance should fail assert(amount <= this.balance).
	owner := helpers.NewWallet()
	recipient := helpers.NewWallet()
	contract, provider, signer := deployInductiveToken(t, owner, 100)

	// Tx1: genesis
	txid1, _, err := contract.Call("send",
		[]interface{}{nil, owner.PubKeyHex(), int64(1)},
		provider, signer,
		&runar.CallOptions{
			NewState: map[string]interface{}{"owner": owner.PubKeyHex()},
			Satoshis: 1,
		})
	if err != nil {
		t.Fatalf("send Tx1 (genesis): %v", err)
	}
	helpers.AssertTxInBlock(t, txid1)

	// Tx2: try to transfer 200 when balance is only 100 -> assert fails
	_, _, err = contract.Call("transfer",
		[]interface{}{nil, recipient.PubKeyHex(), int64(200), int64(1)},
		provider, signer,
		&runar.CallOptions{
			Outputs: []runar.OutputSpec{
				{Satoshis: 1, State: map[string]interface{}{"owner": recipient.PubKeyHex(), "balance": int64(200)}},
				{Satoshis: 1, State: map[string]interface{}{"owner": owner.PubKeyHex(), "balance": int64(-100)}},
			},
			ContinuationOutputIndex: 1,
		})
	if err == nil {
		t.Fatalf("expected transfer exceeding balance to be rejected, but it succeeded")
	}
	t.Logf("transfer correctly rejected overspend: %v", err)
}
