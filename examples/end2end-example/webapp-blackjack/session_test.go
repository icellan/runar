package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// R-152 (CL-BUG-081) — one table per process.
//
// `var game = &GameState{Phase: "welcome"}` was a package-level singleton
// guarded by a mutex. The mutex made concurrent access safe and did nothing
// about every visitor playing the SAME hand: one shoe, one dealer, one set of
// player seats, one set of house UTXOs. One visitor hits and the other sees the
// card land in their own hand.
//
// The server binds `:$PORT` on all interfaces, so "only one person will ever
// open it" is a deployment assumption the code does not make and cannot
// enforce.
//
// These tests drive the handlers with two independent cookie jars and require
// the two to stay apart.

type cookieJar struct {
	cookies []*http.Cookie
}

func (j *cookieJar) send(t *testing.T, h http.HandlerFunc, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	for _, c := range j.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	if issued := rec.Result().Cookies(); len(issued) > 0 {
		j.cookies = issued
	}
	return rec
}

func (j *cookieJar) state(t *testing.T) map[string]any {
	t.Helper()
	rec := j.send(t, handleState, http.MethodGet, "/api/state", nil)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode state: %v (body %s)", err, rec.Body.String())
	}
	return out
}

// seat resolves this jar's session directly and stamps a table size on it.
//
// `/api/new-game` would be the obvious mutation but it funds the house over
// RPC and cannot complete without a regtest node. The property under test is
// the session plumbing — two cookies, two GameStates — and that is reachable
// without the network. The read-back still goes through `handleState`, so a
// handler that resolved the wrong session would still be caught.
func (j *cookieJar) seat(t *testing.T, players int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	for _, c := range j.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	state := sessionFor(rec, req)
	if issued := rec.Result().Cookies(); len(issued) > 0 {
		j.cookies = issued
	}
	state.mu.Lock()
	state.NumPlayers = players
	state.mu.Unlock()
}

func TestSession_TwoVisitorsGetDifferentSessions(t *testing.T) {
	alice, bob := &cookieJar{}, &cookieJar{}
	alice.state(t)
	bob.state(t)

	if len(alice.cookies) == 0 || len(bob.cookies) == 0 {
		t.Fatalf("no session cookie was issued")
	}
	if alice.cookies[0].Value == bob.cookies[0].Value {
		t.Fatalf("both visitors were handed the same session id %q", alice.cookies[0].Value)
	}
}

func TestSession_TablesAreNotShared(t *testing.T) {
	alice, bob := &cookieJar{}, &cookieJar{}

	alice.seat(t, 3)
	bob.seat(t, 6)

	aliceSeats, _ := alice.state(t)["numPlayers"].(float64)
	bobSeats, _ := bob.state(t)["numPlayers"].(float64)

	if int(aliceSeats) != 3 {
		t.Fatalf("the first visitor's table has %v seats, not the 3 they asked for", aliceSeats)
	}
	if int(bobSeats) != 6 {
		t.Fatalf("the second visitor's table has %v seats, not the 6 they asked for", bobSeats)
	}
}

func TestSession_SameCookieKeepsTheSameTable(t *testing.T) {
	// A session key that changed per request would satisfy the isolation tests
	// above while making the app unusable.
	visitor := &cookieJar{}
	visitor.seat(t, 4)

	first, _ := visitor.state(t)["numPlayers"].(float64)
	second, _ := visitor.state(t)["numPlayers"].(float64)
	if int(first) != 4 || int(second) != 4 {
		t.Fatalf("a returning visitor lost their table: %v then %v", first, second)
	}
}

func TestSession_CookieIsNotGuessable(t *testing.T) {
	// A counter or timestamp would let one visitor address another's table by
	// setting the cookie by hand.
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		j := &cookieJar{}
		j.state(t)
		if len(j.cookies) == 0 {
			t.Fatalf("no cookie issued on iteration %d", i)
		}
		v := j.cookies[0].Value
		if len(v) < 32 {
			t.Fatalf("session id %q is only %d chars — too short to be random", v, len(v))
		}
		if seen[v] {
			t.Fatalf("session id %q was issued twice", v)
		}
		seen[v] = true
	}
}
