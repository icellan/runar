package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// R-152 (CL-BUG-081) — per-visitor game state.
//
// The blackjack webapp used to keep `var game = &GameState{Phase: "welcome"}`:
// one game for the whole process, guarded by a mutex. The mutex made concurrent
// access safe and did nothing about the real problem — every visitor was playing
// the SAME hand. Two browsers pointed at one server share a shoe, a dealer, the
// player seats and the house UTXOs; one visitor hits and the other sees the card.
//
// The server binds `:$PORT` on every interface, so "only one person will ever
// open it" is a deployment assumption the code neither makes nor enforces.
//
// State is now keyed by an opaque cookie. The package-level `game` is gone
// deliberately rather than left as a default: with it deleted, any handler that
// forgets to resolve a session fails to compile instead of silently sharing.

const sessionCookieName = "runar_session"

// sessionTTL bounds how long an idle game is kept. A public endpoint that
// allocates a GameState per unseen cookie is an unbounded memory sink
// otherwise — the same class of problem as the unbounded compile body
// `maxCompileBodyBytes` caps.
const sessionTTL = 2 * time.Hour

// maxSessions caps concurrent games regardless of TTL. Reaching it evicts the
// least recently used game rather than refusing service: this is a demo, and a
// visitor whose game is reclaimed simply starts again.
const maxSessions = 256

type session struct {
	state *GameState
	seen  time.Time
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

// newSessionID returns an opaque 256-bit identifier.
//
// Not a counter and not a timestamp: either would let one visitor address
// another visitor's game by setting the cookie by hand, which is the same
// shared-state bug with an extra step.
func newSessionID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not a condition this demo can paper over with
		// a weaker id — that would hand out guessable sessions silently.
		panic("session: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// sessionFor returns the caller's game, creating one and setting the cookie on
// first contact. Every handler that touches game state must start with this.
func sessionFor(w http.ResponseWriter, r *http.Request) *GameState {
	now := time.Now()

	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		sessionsMu.Lock()
		if s, ok := sessions[c.Value]; ok && now.Sub(s.seen) <= sessionTTL {
			s.seen = now
			sessionsMu.Unlock()
			return s.state
		}
		sessionsMu.Unlock()
	}

	id := newSessionID()
	state := &GameState{Phase: "welcome"}

	sessionsMu.Lock()
	pruneSessionsLocked(now)
	sessions[id] = &session{state: state, seen: now}
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
	return state
}

// pruneSessionsLocked drops expired games, then the oldest ones if the map is
// still at capacity. Caller holds sessionsMu.
func pruneSessionsLocked(now time.Time) {
	for id, s := range sessions {
		if now.Sub(s.seen) > sessionTTL {
			delete(sessions, id)
		}
	}
	for len(sessions) >= maxSessions {
		oldestID := ""
		var oldest time.Time
		for id, s := range sessions {
			if oldestID == "" || s.seen.Before(oldest) {
				oldestID, oldest = id, s.seen
			}
		}
		if oldestID == "" {
			return
		}
		delete(sessions, oldestID)
	}
}
