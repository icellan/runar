package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// F-056 (CL-BUG-253) — /api/init must not discard live keys mid-round.
//
// handleInit replaces game.Alice / game.Bob with fresh keypairs. Once a round
// has deployed the PriceBet contract, its locking script commits to the OLD
// pubkeys and the only spend path needs the OLD private keys, which live
// nowhere but this GameState. Re-initializing then leaves the contract UTXO
// unspendable for good. The handler must refuse (409) while a round is in
// flight and allow re-init only from the idle/settled phases.
//
// What these tests prove: the phase guard runs before any key or state is
// touched and before any RPC is issued (a stub node records zero calls), the
// in-RAM keypair survives a refused request, and the idle/settled phases still
// reach the funding step (the stub node is called).
// What they do not prove: anything on-chain. No regtest node is involved, so
// the allowed path is only shown to get past the guard, not to complete.

// stubRPC points the handlers at a fake node that counts calls and fails each
// one, so an allowed init stops at the first funding call instead of hanging
// on a real network.
func stubRPC(t *testing.T) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":null,"error":{"code":-1,"message":"stub node"},"id":1}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("RPC_URL", srv.URL)
	return &calls
}

// sessionAt creates a session for jar and puts its game in the given phase
// with a known keypair, as if a round had progressed that far.
func sessionAt(t *testing.T, jar *cookieJar, phase string) *GameState {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	game := sessionFor(rec, req)
	jar.cookies = rec.Result().Cookies()

	alice, err := newWallet()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := newWallet()
	if err != nil {
		t.Fatal(err)
	}
	game.mu.Lock()
	game.Alice, game.Bob = alice, bob
	game.AlicePubKey, game.BobPubKey = alice.PubKeyHex, bob.PubKeyHex
	game.Inited = true
	game.Round = 1
	game.Phase = phase
	game.ContractTxid = "aa"
	game.Lang = "ts"
	game.mu.Unlock()
	return game
}

func TestInit_RefusedMidRound(t *testing.T) {
	for _, phase := range []string{"betting", "deployed"} {
		t.Run(phase, func(t *testing.T) {
			calls := stubRPC(t)
			jar := &cookieJar{}
			game := sessionAt(t, jar, phase)
			alice, bob := game.Alice, game.Bob

			rec := jar.send(t, handleInit, http.MethodPost, "/api/init", []byte(`{"lang":"sol"}`))

			if rec.Code != http.StatusConflict {
				t.Fatalf("re-init in phase %q returned %d, want 409 (body %s)", phase, rec.Code, rec.Body.String())
			}
			game.mu.Lock()
			defer game.mu.Unlock()
			if game.Alice != alice || game.Bob != bob {
				t.Fatalf("refused re-init still replaced the live keypairs")
			}
			if game.Phase != phase || game.Round != 1 || game.ContractTxid != "aa" || game.Lang != "ts" {
				t.Fatalf("refused re-init mutated state: phase=%q round=%d txid=%q lang=%q",
					game.Phase, game.Round, game.ContractTxid, game.Lang)
			}
			if n := calls.Load(); n != 0 {
				t.Fatalf("refused re-init issued %d RPC calls", n)
			}
		})
	}
}

func TestInit_AllowedWhenIdleOrSettled(t *testing.T) {
	// "funding" is only observable after an init that failed part-way (the
	// handler holds the game lock for the whole init); no contract can exist
	// yet, and refusing would leave the visitor with no way forward.
	for _, phase := range []string{"init", "funding", "ready", "complete"} {
		t.Run(phase, func(t *testing.T) {
			calls := stubRPC(t)
			jar := &cookieJar{}
			sessionAt(t, jar, phase)

			rec := jar.send(t, handleInit, http.MethodPost, "/api/init", []byte(`{}`))

			if rec.Code == http.StatusConflict {
				t.Fatalf("re-init in phase %q was refused: %s", phase, rec.Body.String())
			}
			if calls.Load() == 0 {
				t.Fatalf("re-init in phase %q never reached the funding step (status %d, body %s)",
					phase, rec.Code, rec.Body.String())
			}
		})
	}
}
