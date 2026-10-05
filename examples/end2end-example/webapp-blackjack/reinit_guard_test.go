package main

import (
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// F-056 (CL-BUG-253) — /api/new-game must not discard live keys mid-round.
//
// handleNewGame replaces the house wallet, every player wallet and the Rabin
// oracle keypair. Each BlackjackBet contract deployed by /api/deal bakes the
// oracle pubkey into its locking script, and its only key-free escape
// (`cancel`) needs the player and house keys. Replacing them while those
// contracts are unsettled leaves every contract UTXO unspendable for good. The
// handler must refuse (409) while a round is in flight and allow a new game
// only from the idle/settled phases.
//
// What these tests prove: the phase guard runs before any key or state is
// touched and before any RPC is issued (a stub node records zero calls), the
// in-RAM keys survive a refused request, and the idle/settled phases still
// reach the funding step (the stub node is called).
// What they do not prove: anything on-chain. No regtest node is involved, so
// the allowed path is only shown to get past the guard, not to complete.

// stubRPC points the handlers at a fake node that counts calls and fails each
// one, so an allowed new-game stops at the first funding call instead of
// hanging on a real network.
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

// tableAt creates a session for jar and puts its game in the given phase with
// known house, player and oracle keys, as if a round had progressed that far.
func tableAt(t *testing.T, jar *cookieJar, phase string) *GameState {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	game := sessionFor(rec, req)
	jar.cookies = rec.Result().Cookies()

	house, err := newWallet()
	if err != nil {
		t.Fatal(err)
	}
	player, err := newWallet()
	if err != nil {
		t.Fatal(err)
	}
	game.mu.Lock()
	game.House = house
	game.PlayerWallets = []*Wallet{player}
	game.OracleKeys = &RabinKeyPair{P: big.NewInt(7), Q: big.NewInt(11), N: big.NewInt(77)}
	game.NumPlayers = 1
	game.Round = 1
	game.Phase = phase
	game.mu.Unlock()
	return game
}

func TestNewGame_RefusedMidRound(t *testing.T) {
	for _, phase := range []string{"player-turns", "dealer-turn"} {
		t.Run(phase, func(t *testing.T) {
			calls := stubRPC(t)
			jar := &cookieJar{}
			game := tableAt(t, jar, phase)
			house, players, oracle := game.House, game.PlayerWallets, game.OracleKeys

			rec := jar.send(t, handleNewGame, http.MethodPost, "/api/new-game", []byte(`{"numPlayers":3}`))

			if rec.Code != http.StatusConflict {
				t.Fatalf("new-game in phase %q returned %d, want 409 (body %s)", phase, rec.Code, rec.Body.String())
			}
			game.mu.Lock()
			defer game.mu.Unlock()
			if game.House != house || game.OracleKeys != oracle ||
				len(game.PlayerWallets) != 1 || game.PlayerWallets[0] != players[0] {
				t.Fatalf("refused new-game still replaced the live keys")
			}
			if game.Phase != phase || game.Round != 1 || game.NumPlayers != 1 {
				t.Fatalf("refused new-game mutated state: phase=%q round=%d players=%d",
					game.Phase, game.Round, game.NumPlayers)
			}
			if n := calls.Load(); n != 0 {
				t.Fatalf("refused new-game issued %d RPC calls", n)
			}
		})
	}
}

func TestNewGame_AllowedWhenIdleOrSettled(t *testing.T) {
	// "setup" is only observable after a new-game that failed part-way (the
	// handler holds the game lock throughout); no contract exists yet, and
	// refusing would leave the visitor with no way forward.
	for _, phase := range []string{"welcome", "setup", "ready", "settlement"} {
		t.Run(phase, func(t *testing.T) {
			calls := stubRPC(t)
			jar := &cookieJar{}
			tableAt(t, jar, phase)

			rec := jar.send(t, handleNewGame, http.MethodPost, "/api/new-game", []byte(`{"numPlayers":2}`))

			if rec.Code == http.StatusConflict {
				t.Fatalf("new-game in phase %q was refused: %s", phase, rec.Body.String())
			}
			if calls.Load() == 0 {
				t.Fatalf("new-game in phase %q never reached the funding step (status %d, body %s)",
					phase, rec.Code, rec.Body.String())
			}
		})
	}
}
