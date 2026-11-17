//go:build integration

package integration

import (
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// MessageBoard integration tests — port of integration/ts/message-board.test.ts.
//
// MessageBoard is a stateful contract with a mutable ByteString message and a
// readonly PubKey owner. `post` updates the message (no auth) and `burn`
// terminally spends the contract with the owner's signature. Each test
// deploys the contract and exercises the SDK's auto-state computation +
// auto-signed checkSig path through the BSV regtest node.

var messageBoardArtifact *runar.RunarArtifact
var messageBoardOnce sync.Once

func getMessageBoardArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	messageBoardOnce.Do(func() {
		var err error
		messageBoardArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/message-board/MessageBoard.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile MessageBoard: %v", err)
		}
	})
	return messageBoardArtifact
}

// fundedMessageBoardContract deploys a MessageBoard with the supplied initial
// message and returns the live contract along with the funded wallet's signer
// and provider so the caller can chain Call() invocations.
func fundedMessageBoardContract(t *testing.T, initialMessage string) (*runar.RunarContract, *helpers.BatchRPCProvider, runar.Signer, *helpers.Wallet) {
	t.Helper()
	artifact := getMessageBoardArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{initialMessage, wallet.PubKeyHex()})
	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return contract, provider, signer, wallet
}

// stateMessageHex returns the current `message` state field as the hex string
// the contract advertises through its state map. The SDK normalizes
// ByteString state values to hex strings, so direct equality is safe.
//
// This is the SDK's in-memory prediction (RunarContract.GetState()), NOT a
// read of the actual on-chain bytes — see onChainMessageHex for that.
func stateMessageHex(t *testing.T, c *runar.RunarContract) string {
	t.Helper()
	st := c.GetState()
	v, ok := st["message"]
	if !ok {
		t.Fatalf("state has no 'message' field; got %#v", st)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("state.message is %T, expected string; got %#v", v, v)
	}
	return s
}

// onChainMessageHex decodes the `message` field straight out of the state
// section of the contract's CURRENT on-chain UTXO — the real bytes the node
// just accepted. Deliberately independent of RunarContract.GetState(): the
// SDK's in-memory next-state prediction runs the contract's ANF off-chain,
// the same IR the compiled Script executes, so a miscompilation that makes
// the on-chain script commit a wrong-but-accepted state can produce an
// off-chain prediction that silently agrees with it (PALMER-1, commit
// 23ef2d2b — "the off-chain interpreter agreed... because it evaluates the
// same ANF"). Reading the state section back out of the broadcast
// transaction's own script bytes does not go through that computation.
func onChainMessageHex(t *testing.T, artifact *runar.RunarArtifact, c *runar.RunarContract) string {
	t.Helper()
	utxo := c.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("onChainMessageHex: no current UTXO tracked on the contract")
	}
	state, err := helpers.ReadOnChainState(artifact, utxo.Txid, utxo.OutputIndex)
	if err != nil {
		t.Fatalf("onChainMessageHex: %v", err)
	}
	v, ok := state["message"]
	if !ok {
		t.Fatalf("onChainMessageHex: on-chain state has no 'message' field; got %#v", state)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("onChainMessageHex: on-chain state.message is %T, expected string; got %#v", v, v)
	}
	return s
}

// ---------------------------------------------------------------------------
// post: update the message (no signature required)
// ---------------------------------------------------------------------------

func TestMessageBoard_PostInitialMessage(t *testing.T) {
	artifact := getMessageBoardArtifact(t)
	contract, provider, signer, _ := fundedMessageBoardContract(t, "00")
	defer provider.MineAll()

	txid, _, err := contract.Call("post", []interface{}{"48656c6c6f"}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call post: %v", err)
	}
	t.Logf("post TX confirmed: %s", txid)

	if got := stateMessageHex(t, contract); got != "48656c6c6f" {
		t.Fatalf("state.message after post: got %q, want %q", got, "48656c6c6f")
	}
	if got := onChainMessageHex(t, artifact, contract); got != "48656c6c6f" {
		t.Fatalf("on-chain state.message after post: got %q, want %q", got, "48656c6c6f")
	}
}

func TestMessageBoard_ChainPosts(t *testing.T) {
	artifact := getMessageBoardArtifact(t)
	contract, provider, signer, _ := fundedMessageBoardContract(t, "00")
	defer provider.MineAll()

	if _, _, err := contract.Call("post", []interface{}{"aabb"}, provider, signer, nil); err != nil {
		t.Fatalf("first post: %v", err)
	}
	if got := stateMessageHex(t, contract); got != "aabb" {
		t.Fatalf("state after first post: got %q, want %q", got, "aabb")
	}
	if got := onChainMessageHex(t, artifact, contract); got != "aabb" {
		t.Fatalf("on-chain state after first post: got %q, want %q", got, "aabb")
	}

	if _, _, err := contract.Call("post", []interface{}{"ccddee"}, provider, signer, nil); err != nil {
		t.Fatalf("second post: %v", err)
	}
	if got := stateMessageHex(t, contract); got != "ccddee" {
		t.Fatalf("state after second post: got %q, want %q", got, "ccddee")
	}
	if got := onChainMessageHex(t, artifact, contract); got != "ccddee" {
		t.Fatalf("on-chain state after second post: got %q, want %q", got, "ccddee")
	}
}

// ---------------------------------------------------------------------------
// burn: terminal spend gated by the owner's signature
// ---------------------------------------------------------------------------

func TestMessageBoard_BurnByOwner(t *testing.T) {
	contract, provider, signer, _ := fundedMessageBoardContract(t, "00")
	defer provider.MineAll()

	txid, _, err := contract.Call("burn", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("burn: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("burn TX confirmed: %s", txid)
}

func TestMessageBoard_BurnByWrongSigner_Rejected(t *testing.T) {
	contract, provider, _, _ := fundedMessageBoardContract(t, "00")
	defer provider.MineAll()

	wrongWallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wrongWallet.Address, "", false)
	if _, err := helpers.FundWallet(wrongWallet, 1.0); err != nil {
		t.Fatalf("fund wrong wallet: %v", err)
	}
	wrongSigner, err := helpers.SDKSignerFromWallet(wrongWallet)
	if err != nil {
		t.Fatalf("wrong signer: %v", err)
	}

	before := provider.BroadcastAttempts
	_, _, callErr := contract.Call("burn", []interface{}{nil}, provider, wrongSigner, nil)
	if callErr == nil {
		t.Fatalf("expected burn by wrong signer to be rejected, but it succeeded")
	}
	if bad := helpers.CheckNodeRejected(provider, before, callErr, helpers.ScriptVerifyFailed); bad != nil {
		t.Fatalf("not a node rejection: %v", bad)
	}
}

// ---------------------------------------------------------------------------
// Empty initial message: deploy with "" and then post
// ---------------------------------------------------------------------------

func TestMessageBoard_DeployEmptyThenPost(t *testing.T) {
	artifact := getMessageBoardArtifact(t)
	contract, provider, signer, _ := fundedMessageBoardContract(t, "")
	defer provider.MineAll()

	txid, _, err := contract.Call("post", []interface{}{"48656c6c6f"}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call post: %v", err)
	}
	t.Logf("post TX confirmed: %s", txid)
	if got := stateMessageHex(t, contract); got != "48656c6c6f" {
		t.Fatalf("state.message after post: got %q, want %q", got, "48656c6c6f")
	}
	if got := onChainMessageHex(t, artifact, contract); got != "48656c6c6f" {
		t.Fatalf("on-chain state.message after post: got %q, want %q", got, "48656c6c6f")
	}
}
