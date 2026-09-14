package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// R-152 (CL-BUG-081) — one visitor per process.
//
// `var game = &GameState{Phase: "init"}` was a package-level singleton guarded
// by a mutex. The mutex made concurrent access safe; it did nothing about the
// fact that every visitor was looking at the SAME game. Two browsers pointed at
// one server share a round, a threshold, a pair of wallets and a contract UTXO:
// whoever bets second overwrites the first, and `/api/state` hands each of them
// the other's position. There was no session key anywhere in either webapp.
//
// The server binds `:$PORT` on all interfaces, so "only one person will ever
// open it" is a deployment assumption the code does not make and cannot
// enforce.
//
// State is now keyed by a cookie. These tests drive the handlers with two
// independent cookie jars and require the two to stay apart.

// cookieJar is the minimal slice of http.CookieJar these tests need: carry
// whatever Set-Cookie the server issued into the next request.
type cookieJar struct {
	cookies []*http.Cookie
}

func (j *cookieJar) do(t *testing.T, h http.HandlerFunc, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	return j.send(t, h, method, target, nil)
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
	rec := j.do(t, handleState, http.MethodGet, "/api/state")
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode state: %v (body %s)", err, rec.Body.String())
	}
	return out
}

func TestSession_TwoVisitorsGetDifferentSessions(t *testing.T) {
	alice := &cookieJar{}
	bob := &cookieJar{}

	alice.state(t)
	bob.state(t)

	if len(alice.cookies) == 0 {
		t.Fatalf("no session cookie was issued")
	}
	if len(bob.cookies) == 0 {
		t.Fatalf("second visitor got no session cookie")
	}
	if alice.cookies[0].Value == bob.cookies[0].Value {
		t.Fatalf("both visitors were handed the same session id %q", alice.cookies[0].Value)
	}
}

// setLang mutates one visitor's game through a handler that needs no regtest
// node, so these tests stay hermetic. `/api/init` would be the more obvious
// mutation but it cannot complete without a funded node.
func (j *cookieJar) setLang(t *testing.T, lang string) {
	t.Helper()
	rec := j.send(t, handleLang, http.MethodPost, "/api/lang",
		[]byte(`{"lang":"`+lang+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("set lang %s: %d %s", lang, rec.Code, rec.Body.String())
	}
}

func TestSession_StateIsNotShared(t *testing.T) {
	alice := &cookieJar{}
	bob := &cookieJar{}

	alice.setLang(t, "rb")
	bob.setLang(t, "zig")

	aliceLang, _ := alice.state(t)["lang"].(string)
	bobLang, _ := bob.state(t)["lang"].(string)

	if aliceLang != "rb" {
		t.Fatalf("the first visitor lost their own setting: %q", aliceLang)
	}
	if bobLang != "zig" {
		t.Fatalf("the second visitor sees %q, not their own selection", bobLang)
	}
}

func TestSession_SameCookieKeepsTheSameGame(t *testing.T) {
	// The flip side: a session key that changed per request would pass the two
	// tests above while making the app unusable.
	visitor := &cookieJar{}
	visitor.setLang(t, "move")

	first := visitor.state(t)
	second := visitor.state(t)

	firstLang, _ := first["lang"].(string)
	secondLang, _ := second["lang"].(string)
	if firstLang != "move" || secondLang != "move" {
		t.Fatalf("a returning visitor lost their game: %q then %q", firstLang, secondLang)
	}
	if first["alicePubKey"] != second["alicePubKey"] {
		t.Fatalf("same cookie produced different wallets: %v vs %v",
			first["alicePubKey"], second["alicePubKey"])
	}
}

func TestSession_CookieIsNotGuessable(t *testing.T) {
	// A counter or a timestamp would let one visitor address another's game by
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
