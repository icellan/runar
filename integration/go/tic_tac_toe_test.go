//go:build integration

package integration

import (
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

func compileTicTacToe(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/tic-tac-toe/TicTacToe.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return artifact
}

func deployTicTacToe(t *testing.T, playerXWallet *helpers.Wallet, betAmount int64) (*runar.RunarContract, runar.Provider, runar.Signer) {
	t.Helper()

	artifact := compileTicTacToe(t)
	t.Logf("TicTacToe script: %d bytes", len(artifact.Script)/2)

	// Constructor params: playerX (PubKey), betAmount (Bigint)
	contract := runar.NewRunarContract(artifact, []interface{}{
		playerXWallet.PubKeyHex(), int64(betAmount),
	})

	helpers.RPCCall("importaddress", playerXWallet.Address, "", false)
	_, err := helpers.FundWallet(playerXWallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(playerXWallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: betAmount})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return contract, provider, signer
}

func TestTicTacToe_Compile(t *testing.T) {
	artifact := compileTicTacToe(t)
	if artifact.ContractName != "TicTacToe" {
		t.Fatalf("expected contract name TicTacToe, got %s", artifact.ContractName)
	}
	t.Logf("TicTacToe compiled: %d bytes", len(artifact.Script)/2)
}

func TestTicTacToe_Deploy(t *testing.T) {
	playerX := helpers.NewWallet()
	contract, _, _ := deployTicTacToe(t, playerX, 5000)
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("no UTXO after deploy")
	}
	t.Logf("deployed TicTacToe with betAmount=5000")
}

func TestTicTacToe_Join(t *testing.T) {
	playerX := helpers.NewWallet()
	playerO := helpers.NewWallet()

	contract, provider, _ := deployTicTacToe(t, playerX, 5000)

	// Fund playerO wallet so they can pay fees
	helpers.RPCCall("importaddress", playerO.Address, "", false)
	_, err := helpers.FundWallet(playerO, 1.0)
	if err != nil {
		t.Fatalf("fund playerO: %v", err)
	}
	playerOSigner, err := helpers.SDKSignerFromWallet(playerO)
	if err != nil {
		t.Fatalf("playerO signer: %v", err)
	}

	// join(opponentPK, sig) — method index 0
	// sig is nil (auto-computed), opponentPK is playerO's pubkey
	txid, _, err := contract.Call("join",
		[]interface{}{playerO.PubKeyHex(), nil},
		provider, playerOSigner, nil)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	t.Logf("join TX: %s", txid)
}

func TestTicTacToe_Move(t *testing.T) {
	playerX := helpers.NewWallet()
	playerO := helpers.NewWallet()

	contract, provider, signerX := deployTicTacToe(t, playerX, 5000)

	// Fund playerO
	helpers.RPCCall("importaddress", playerO.Address, "", false)
	_, err := helpers.FundWallet(playerO, 1.0)
	if err != nil {
		t.Fatalf("fund playerO: %v", err)
	}
	signerO, err := helpers.SDKSignerFromWallet(playerO)
	if err != nil {
		t.Fatalf("playerO signer: %v", err)
	}

	// Join
	_, _, err = contract.Call("join",
		[]interface{}{playerO.PubKeyHex(), nil},
		provider, signerO, nil)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Move: player X plays position 4 (center)
	txid, _, err := contract.Call("move",
		[]interface{}{int64(4), playerX.PubKeyHex(), nil},
		provider, signerX, nil)
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("move TX: %s", txid)
}

func TestTicTacToe_FullGame(t *testing.T) {
	playerX := helpers.NewWallet()
	playerO := helpers.NewWallet()

	betAmount := int64(1000)
	contract, provider, signerX := deployTicTacToe(t, playerX, betAmount)

	// Fund playerO
	helpers.RPCCall("importaddress", playerO.Address, "", false)
	_, err := helpers.FundWallet(playerO, 1.0)
	if err != nil {
		t.Fatalf("fund playerO: %v", err)
	}
	signerO, err := helpers.SDKSignerFromWallet(playerO)
	if err != nil {
		t.Fatalf("playerO signer: %v", err)
	}

	px := playerX.PubKeyHex()
	po := playerO.PubKeyHex()

	// Join — doubles the pot (betAmount * 2)
	_, _, err = contract.Call("join",
		[]interface{}{po, nil},
		provider, signerO,
		&runar.CallOptions{Satoshis: betAmount * 2})
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
	_, _, err = contract.Call("move",
		[]interface{}{int64(0), px, nil},
		provider, signerX, nil)
	if err != nil {
		t.Fatalf("move X@0: %v", err)
	}

	_, _, err = contract.Call("move",
		[]interface{}{int64(3), po, nil},
		provider, signerO, nil)
	if err != nil {
		t.Fatalf("move O@3: %v", err)
	}

	_, _, err = contract.Call("move",
		[]interface{}{int64(1), px, nil},
		provider, signerX, nil)
	if err != nil {
		t.Fatalf("move X@1: %v", err)
	}

	_, _, err = contract.Call("move",
		[]interface{}{int64(4), po, nil},
		provider, signerO, nil)
	if err != nil {
		t.Fatalf("move O@4: %v", err)
	}

	// Board: X X _ | O O _ | _ _ _ — X plays position 2 to win top row
	// moveAndWin(position, player, sig, changePKH, changeAmount)
	totalPayout := betAmount * 2
	winnerP2PKH := "76a914" + playerX.PubKeyHashHex() + "88ac"

	txid, _, err := contract.Call("moveAndWin",
		[]interface{}{int64(2), px, nil, "0000000000000000000000000000000000000000", int64(0)},
		provider, signerX,
		&runar.CallOptions{
			TerminalOutputs: []runar.TerminalOutput{
				{ScriptHex: winnerP2PKH, Satoshis: totalPayout},
			},
		})
	if err != nil {
		t.Fatalf("moveAndWin: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("moveAndWin TX: %s (payout %d sat to %s)", txid, totalPayout, playerX.Address)
}

func TestTicTacToe_WrongPlayerRejected(t *testing.T) {
	playerX := helpers.NewWallet()
	playerO := helpers.NewWallet()

	contract, provider, _ := deployTicTacToe(t, playerX, 5000)

	// Fund playerO
	helpers.RPCCall("importaddress", playerO.Address, "", false)
	_, err := helpers.FundWallet(playerO, 1.0)
	if err != nil {
		t.Fatalf("fund playerO: %v", err)
	}
	playerOSigner, err := helpers.SDKSignerFromWallet(playerO)
	if err != nil {
		t.Fatalf("playerO signer: %v", err)
	}

	// Join
	_, _, err = contract.Call("join",
		[]interface{}{playerO.PubKeyHex(), nil},
		provider, playerOSigner, nil)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// After join, turn=1 (X's turn). Try to move with O's key — should fail
	// because assertCorrectPlayer checks player == playerX when turn==1
	_, _, err = contract.Call("move",
		[]interface{}{int64(4), playerO.PubKeyHex(), nil},
		provider, playerOSigner, nil)
	if err == nil {
		t.Fatalf("expected move with wrong player to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected wrong player: %v", err)
}

func TestTicTacToe_JoinAfterPlayingRejected(t *testing.T) {
	playerX := helpers.NewWallet()
	playerO := helpers.NewWallet()

	contract, provider, _ := deployTicTacToe(t, playerX, 5000)

	// Fund playerO
	helpers.RPCCall("importaddress", playerO.Address, "", false)
	_, err := helpers.FundWallet(playerO, 1.0)
	if err != nil {
		t.Fatalf("fund playerO: %v", err)
	}
	playerOSigner, err := helpers.SDKSignerFromWallet(playerO)
	if err != nil {
		t.Fatalf("playerO signer: %v", err)
	}

	// Join
	_, _, err = contract.Call("join",
		[]interface{}{playerO.PubKeyHex(), nil},
		provider, playerOSigner, nil)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// Try to join again — should fail because status != 0
	_, _, err = contract.Call("join",
		[]interface{}{playerO.PubKeyHex(), nil},
		provider, playerOSigner, nil)
	if err == nil {
		t.Fatalf("expected second join to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected second join: %v", err)
}
