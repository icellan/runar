package main

// F-162 (CL-BUG-255) — the webapp's round is settled through PriceBet.settle,
// signed by its own oracle, and that spend is valid.
//
// This file BUILDS the transactions; it does not judge them. The verdict comes
// from @bsv/sdk Spend in tests/f162-webapp-settle-spends.test.ts, which runs
// this test with F162_SETTLE_VECTORS set and replays every vector. Judging here
// with the Go compiler's own model would grade the compiler against itself.
//
// Every vector is produced by the webapp's own code: gameLockingScript (the
// script deployContract broadcasts) and settleRound (the spend handleReveal
// broadcasts). Only the negatives call buildSettleTx directly, to plant one
// specific defect each.

import (
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type settleVector struct {
	Name       string `json:"name"`
	FundingTx  string `json:"fundingTx"`
	SettleTx   string `json:"settleTx"`
	Expect     string `json:"expect"` // "accept" | "reject"
	WinnerAddr string `json:"winnerP2PKH,omitempty"`
}

// deployedGame returns a game whose contract output sits at vout 0 of a
// synthetic funding tx (never broadcast; Spend only needs the prevout).
func deployedGame(t *testing.T, aliceBet string, threshold int) (*GameState, string) {
	t.Helper()
	alice, err := newWallet()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := newWallet()
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := newRabinKey()
	if err != nil {
		t.Fatal(err)
	}
	game := &GameState{Alice: alice, Bob: bob, Oracle: oracle, Lang: "ts", Threshold: threshold, AliceBet: aliceBet}
	if aliceBet == "over" {
		game.BobBet = "under"
	} else {
		game.BobBet = "over"
	}

	lockingHex, err := gameLockingScript(game)
	if err != nil {
		t.Fatalf("gameLockingScript: %v", err)
	}
	game.LockingScript = lockingHex

	funding := transaction.NewTransaction()
	if err := funding.AddInputFrom(strings.Repeat("11", 32), 0, alice.P2PKH, 1_000_000, nil); err != nil {
		t.Fatal(err)
	}
	funding.Inputs[0].UnlockingScript = &script.Script{}
	lock, err := script.NewFromHex(lockingHex)
	if err != nil {
		t.Fatal(err)
	}
	funding.AddOutput(&transaction.TransactionOutput{Satoshis: contractSats, LockingScript: lock})
	game.ContractTxid = funding.TxID().String()
	game.ContractVout = 0
	return game, funding.String()
}

func contractUTXOOf(game *GameState) *UTXO {
	return &UTXO{Txid: game.ContractTxid, Vout: game.ContractVout, Satoshis: contractSats, Script: game.LockingScript}
}

func TestF162SettleVectors(t *testing.T) {
	var vectors []settleVector

	settled := func(name, aliceBet string, threshold int, price int64, wantWinner string) {
		game, funding := deployedGame(t, aliceBet, threshold)
		txHex, winner, winnerP2PKH, err := settleRound(game, price)
		if err != nil {
			t.Fatalf("%s: settleRound: %v", name, err)
		}
		if winner != wantWinner {
			t.Fatalf("%s: settleRound picked %s, want %s", name, winner, wantWinner)
		}
		vectors = append(vectors, settleVector{Name: name, FundingTx: funding, SettleTx: txHex, Expect: "accept", WinnerAddr: winnerP2PKH})
	}

	// Positives: the exact spend handleReveal broadcasts.
	settled("alice bets over, price 73 > 50: alice settles alone", "over", 50, 73, "alice")
	settled("alice bets under, price 73 > 50: bob (over) settles alone", "under", 50, 73, "bob")
	settled("price 50 == threshold 50: under (alice) settles alone", "under", 50, 50, "alice")
	settled("price 7 (an OP_7 push) < 50: under (bob) settles alone", "over", 50, 7, "bob")

	// Negatives, all against one contract: alice bet over, threshold 50.
	game, funding := deployedGame(t, "over", 50)
	utxo := contractUTXOOf(game)
	sig73, pad73, err := game.Oracle.sign(priceMessage(73))
	if err != nil {
		t.Fatal(err)
	}
	reject := func(name string, price int64, sig, pad *big.Int, signer *Wallet, slot int) {
		txHex, err := buildSettleTx(utxo, signer.P2PKH, contractSats, price, sig, pad, signer, slot)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		vectors = append(vectors, settleVector{Name: name, FundingTx: funding, SettleTx: txHex, Expect: "reject"})
	}
	reject("price 73 > 50 but only the loser (bob) signs, in alice's slot", 73, sig73, pad73, game.Bob, aliceSigSlot)
	reject("price 73 > 50 but only the loser (bob) signs, in his own slot", 73, sig73, pad73, game.Bob, bobSigSlot)
	reject("oracle signed 73, spender claims 74 (alice's arm either way)", 74, sig73, pad73, game.Alice, aliceSigSlot)
	// The forgery the old hard-coded oracleN = 12345 admitted: verifyRabinSig
	// reduces the digest mod the key, so sig = 0 with padding = digest mod
	// 12345 (< 65536, inside the padding range check) satisfies it for any
	// price, with no oracle involved.
	h := sha256.Sum256(priceMessage(73))
	forgedPad := new(big.Int).Mod(leUnsigned(h[:]), big.NewInt(12345))
	reject("forged oracle signature: sig 0, padding = SHA256(msg) mod 12345", 73, big.NewInt(0), forgedPad, game.Alice, aliceSigSlot)

	out := os.Getenv("F162_SETTLE_VECTORS")
	if out == "" {
		out = filepath.Join(t.TempDir(), "settle-vectors.json")
	}
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
