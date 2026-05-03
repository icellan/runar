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

// ---------------------------------------------------------------------------
// post: update the message (no signature required)
// ---------------------------------------------------------------------------

func TestMessageBoard_PostInitialMessage(t *testing.T) {
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
}

func TestMessageBoard_ChainPosts(t *testing.T) {
	contract, provider, signer, _ := fundedMessageBoardContract(t, "00")
	defer provider.MineAll()

	if _, _, err := contract.Call("post", []interface{}{"aabb"}, provider, signer, nil); err != nil {
		t.Fatalf("first post: %v", err)
	}
	if got := stateMessageHex(t, contract); got != "aabb" {
		t.Fatalf("state after first post: got %q, want %q", got, "aabb")
	}

	if _, _, err := contract.Call("post", []interface{}{"ccddee"}, provider, signer, nil); err != nil {
		t.Fatalf("second post: %v", err)
	}
	if got := stateMessageHex(t, contract); got != "ccddee" {
		t.Fatalf("state after second post: got %q, want %q", got, "ccddee")
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

	if _, _, err := contract.Call("burn", []interface{}{nil}, provider, wrongSigner, nil); err == nil {
		t.Fatalf("expected burn by wrong signer to be rejected, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Empty initial message: deploy with "" and then post
// ---------------------------------------------------------------------------

func TestMessageBoard_DeployEmptyThenPost(t *testing.T) {
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
}
