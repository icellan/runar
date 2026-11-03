package main

import (
	"net/http"
	"testing"
)

// N-118 — new-game and new-round must refuse while any contract this session
// deployed has not reached a recorded settle txid.
//
// F-056 closed "new-game replaces keys mid-round" by gating on game.Phase,
// but phase alone is not a reliable proxy for "nothing is stranded":
//   (a) handleDeal can fail after deploying some players' contracts and
//       return with Phase still "ready" — a phase new-game already allows.
//   (b) handleDealer sets Phase "settlement" unconditionally, even for a
//       contract whose settle call failed and the loop `continue`d past.
//   (c) handleNewRound only checks Phase == "settlement" and then
//       unconditionally wipes game.Contracts, discarding the only record of
//       a contract that never settled.
// All three leave a ContractState with a non-empty ContractTxid and an empty
// SettleTxid. Producing that state via a real deploy/settle needs a regtest
// node (same reason F-056's own tests use tableAt instead); these tests
// fabricate it directly on top of tableAt and check the guard, not the
// deploy/settle call that would normally produce the state.
//
// What these tests prove: new-game and new-round both refuse (409, no RPC,
// the unsettled contract record and live keys left untouched) whenever
// game.Contracts holds a deployed-but-unsettled entry, regardless of which
// of the three paths produced it — and both still proceed once every
// contract carries a SettleTxid.
// What they do not prove: that handleDeal/handleDealer actually reach this
// state against a live node — only that the guard reacts correctly once they
// do.

// withContract returns tableAt's game with one ContractState recorded for
// player 0: always deployed (non-empty ContractTxid), settled only if
// settled is true.
func withContract(t *testing.T, jar *cookieJar, phase string, settled bool) *GameState {
	t.Helper()
	game := tableAt(t, jar, phase)
	cs := ContractState{PlayerIndex: 0, ContractTxid: "deadbeef"}
	if settled {
		cs.SettleTxid = "f00dface"
	}
	game.mu.Lock()
	game.Contracts = []ContractState{cs}
	game.mu.Unlock()
	return game
}

func TestNewGame_RefusedAfterPartialDeal(t *testing.T) {
	// (a): a deal that deployed player 0's contract and then failed before
	// reaching the end of handleDeal leaves Phase == "ready" — handleDeal
	// only advances Phase after every player is dealt — with Contracts[0]
	// recording the deploy but no settle.
	calls := stubRPC(t)
	jar := &cookieJar{}
	game := withContract(t, jar, "ready", false)
	house, players, oracle := game.House, game.PlayerWallets, game.OracleKeys

	rec := jar.send(t, handleNewGame, http.MethodPost, "/api/new-game", []byte(`{"numPlayers":1}`))

	if rec.Code != http.StatusConflict {
		t.Fatalf("new-game with an unsettled contract (phase ready) returned %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	game.mu.Lock()
	defer game.mu.Unlock()
	if game.House != house || game.OracleKeys != oracle ||
		len(game.PlayerWallets) != 1 || game.PlayerWallets[0] != players[0] {
		t.Fatalf("refused new-game still replaced the live keys")
	}
	if len(game.Contracts) != 1 || game.Contracts[0].SettleTxid != "" {
		t.Fatalf("refused new-game touched the unsettled contract record")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("refused new-game issued %d RPC calls", n)
	}
}

func TestNewGame_RefusedAfterFailedSettle(t *testing.T) {
	// (b): handleDealer sets Phase "settlement" even when a settle call
	// failed and it `continue`d, leaving the contract's SettleTxid empty.
	calls := stubRPC(t)
	jar := &cookieJar{}
	game := withContract(t, jar, "settlement", false)
	house, oracle := game.House, game.OracleKeys

	rec := jar.send(t, handleNewGame, http.MethodPost, "/api/new-game", []byte(`{"numPlayers":1}`))

	if rec.Code != http.StatusConflict {
		t.Fatalf("new-game with an unsettled contract (phase settlement) returned %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	game.mu.Lock()
	defer game.mu.Unlock()
	if game.House != house || game.OracleKeys != oracle {
		t.Fatalf("refused new-game still replaced the live keys")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("refused new-game issued %d RPC calls", n)
	}
}

func TestNewRound_RefusedWithUnsettledContract(t *testing.T) {
	// (c): handleNewRound only checks Phase == "settlement" today and then
	// unconditionally wipes game.Contracts, discarding the only record of a
	// contract whose settle failed.
	jar := &cookieJar{}
	game := withContract(t, jar, "settlement", false)

	rec := jar.send(t, handleNewRound, http.MethodPost, "/api/new-round", nil)

	if rec.Code != http.StatusConflict {
		t.Fatalf("new-round with an unsettled contract returned %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	game.mu.Lock()
	defer game.mu.Unlock()
	if game.Phase != "settlement" {
		t.Fatalf("refused new-round still advanced phase to %q", game.Phase)
	}
	if len(game.Contracts) != 1 || game.Contracts[0].SettleTxid != "" {
		t.Fatalf("refused new-round wiped the unsettled contract record")
	}
}

func TestDeal_RefusedOnRetryAfterPartialDeal(t *testing.T) {
	// Dispatcher follow-up on N-118: a retried /api/deal after a partial deal
	// (Phase stuck "ready", player 0's contract deployed but not settled)
	// must not run `game.Contracts = make(...)` — that would erase the only
	// record the new-game/new-round guards depend on, reopening the hole they
	// close. handleDeal must refuse instead, leaving keys and the contract
	// record untouched and issuing no RPC call, and the record must still be
	// there afterward for new-game's guard to catch.
	calls := stubRPC(t)
	jar := &cookieJar{}
	game := withContract(t, jar, "ready", false)
	house, players, oracle := game.House, game.PlayerWallets, game.OracleKeys

	rec := jar.send(t, handleDeal, http.MethodPost, "/api/deal", nil)

	if rec.Code != http.StatusConflict {
		t.Fatalf("deal retry with an unsettled contract returned %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	game.mu.Lock()
	if game.House != house || game.OracleKeys != oracle ||
		len(game.PlayerWallets) != 1 || game.PlayerWallets[0] != players[0] {
		game.mu.Unlock()
		t.Fatalf("refused deal retry still replaced the live keys")
	}
	if len(game.Contracts) != 1 || game.Contracts[0].ContractTxid == "" || game.Contracts[0].SettleTxid != "" {
		game.mu.Unlock()
		t.Fatalf("refused deal retry touched the unsettled contract record")
	}
	game.mu.Unlock()
	if n := calls.Load(); n != 0 {
		t.Fatalf("refused deal retry issued %d RPC calls", n)
	}

	// The record the new-game guard depends on must still be there: a
	// new-game attempted right after must still be refused.
	rec2 := jar.send(t, handleNewGame, http.MethodPost, "/api/new-game", []byte(`{"numPlayers":1}`))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("new-game after a refused deal retry returned %d, want 409 (body %s)", rec2.Code, rec2.Body.String())
	}
}

func TestNewGameAndNewRound_AllowedWhenAllContractsSettled(t *testing.T) {
	// Control: once every contract carries a SettleTxid, both endpoints must
	// still proceed past the guard — it must not refuse more than the
	// stranding paths it closes.
	t.Run("new-game", func(t *testing.T) {
		calls := stubRPC(t)
		jar := &cookieJar{}
		withContract(t, jar, "settlement", true)

		rec := jar.send(t, handleNewGame, http.MethodPost, "/api/new-game", []byte(`{"numPlayers":1}`))

		if rec.Code == http.StatusConflict {
			t.Fatalf("new-game with a settled contract was refused: %s", rec.Body.String())
		}
		if calls.Load() == 0 {
			t.Fatalf("new-game with a settled contract never reached the funding step (status %d, body %s)",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("new-round", func(t *testing.T) {
		jar := &cookieJar{}
		game := withContract(t, jar, "settlement", true)

		rec := jar.send(t, handleNewRound, http.MethodPost, "/api/new-round", nil)

		if rec.Code != http.StatusOK {
			t.Fatalf("new-round with a settled contract returned %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		game.mu.Lock()
		defer game.mu.Unlock()
		if game.Phase != "ready" {
			t.Fatalf("new-round with a settled contract left phase %q, want ready", game.Phase)
		}
	})
}
