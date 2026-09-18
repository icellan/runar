package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/icellan/runar/compilers/go/ir"
)

const contractSats = 20000

// maxCompileBodyBytes caps the /api/compile request body. The endpoint is
// unauthenticated and hands caller-supplied bytes to the full compiler
// pipeline, so an unbounded body is a free amplification primitive: the cap
// is enforced while reading, not after buffering. 1 MiB is ~300x the largest
// bundled example contract.
//
// A variable rather than a constant so tests can shrink it.
var maxCompileBodyBytes int64 = 1 << 20 // 1 MiB

// compileTimeout bounds a single playground compile so no one request can
// occupy a handler goroutine indefinitely. Must stay below serverWriteTimeout
// or the connection is torn down before the error response is written.
var compileTimeout = 10 * time.Second

// Connection-level deadlines. Without these a bare http.ListenAndServe lets a
// slowloris client hold a connection (and its goroutine) open forever.
const (
	serverReadTimeout  = 15 * time.Second
	serverWriteTimeout = 30 * time.Second
	serverIdleTimeout  = 60 * time.Second
)

type RoundResult struct {
	Round     int    `json:"round"`
	Threshold int    `json:"threshold"`
	Oracle    int    `json:"oracle"`
	AliceBet  string `json:"aliceBet"`
	BobBet    string `json:"bobBet"`
	Winner    string `json:"winner"`
	DeployTx  string `json:"deployTx"`
	SpendTx   string `json:"spendTx"`
}

type GameState struct {
	mu sync.Mutex

	Alice   *Wallet `json:"-"`
	Bob     *Wallet `json:"-"`
	Inited  bool    `json:"inited"`
	Phase   string  `json:"phase"`
	Round   int     `json:"round"`
	History []RoundResult `json:"history"`

	Threshold     int    `json:"threshold"`
	AliceBet      string `json:"aliceBet"`
	BobBet        string `json:"bobBet"`
	LockingScript string `json:"-"`
	ContractTxid  string `json:"contractTxid"`
	ContractVout  uint32 `json:"-"`

	AlicePubKey string `json:"alicePubKey"`
	BobPubKey   string `json:"bobPubKey"`
	AliceAddr   string `json:"aliceAddr"`
	BobAddr     string `json:"bobAddr"`
	AliceBalance int64 `json:"aliceBalance"`
	BobBalance   int64 `json:"bobBalance"`

	// Lang selects which PriceBet source variant the backend compiles when
	// deploying the contract ("ts" (default), "sol", "move", "go", "rs",
	// "py", "rb", "zig", or "java"). The Go compiler dispatches to the
	// matching parser via the filename extension in compiler.go.
	Lang string `json:"lang"`

	AliceUTXO *UTXO `json:"-"`
	BobUTXO   *UTXO `json:"-"`

	Log []LogEntry `json:"log"`
}

type LogEntry struct {
	Message string `json:"message"`
	Txid    string `json:"txid,omitempty"`
	Type    string `json:"type"`
}



func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := newServer(port)

	log.Printf("PriceBet webapp listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func newServer(port string) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/init", handleInit)
	mux.HandleFunc("/api/state", handleState)
	mux.HandleFunc("/api/round/new", handleNewRound)
	mux.HandleFunc("/api/round/bet", handleBet)
	mux.HandleFunc("/api/round/reveal", handleReveal)
	mux.HandleFunc("/api/compile", handleCompile)
	mux.HandleFunc("/api/lang", handleLang)
	mux.HandleFunc("/api/template", handleTemplate)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "static/index.html")
	})

	return &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       serverReadTimeout,
		ReadHeaderTimeout: serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func handleInit(w http.ResponseWriter, r *http.Request) {
	// R-152: resolve this visitor's game. The package-level singleton is gone,
	// so a handler that forgets this does not compile.
	game := sessionFor(w, r)
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	// Optional JSON body: { "lang": "ts" | "sol" | ... | "java" }. Missing
	// or empty body falls through to the default (TypeScript).
	var req struct {
		Lang string `json:"lang"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	game.mu.Lock()
	defer game.mu.Unlock()

	game.Lang = normalizeLang(req.Lang)

	alice, err := newWallet()
	if err != nil {
		jsonError(w, fmt.Sprintf("create alice wallet: %v", err), 500)
		return
	}

	bob, err := newWallet()
	if err != nil {
		jsonError(w, fmt.Sprintf("create bob wallet: %v", err), 500)
		return
	}

	game.Alice = alice
	game.Bob = bob
	game.AlicePubKey = alice.PubKeyHex
	game.BobPubKey = bob.PubKeyHex
	game.AliceAddr = alice.Address
	game.BobAddr = bob.Address
	game.History = nil
	game.Log = nil
	game.Round = 0
	game.Phase = "funding"

	aliceTxid, err := fundWallet(alice.Address, 10.0)
	if err != nil {
		jsonError(w, fmt.Sprintf("fund alice: %v", err), 500)
		return
	}
	game.Log = append(game.Log, LogEntry{
		Message: "Alice funded: 10 BTC",
		Txid:    aliceTxid,
		Type:    "fund",
	})

	bobTxid, err := fundWallet(bob.Address, 10.0)
	if err != nil {
		jsonError(w, fmt.Sprintf("fund bob: %v", err), 500)
		return
	}
	game.Log = append(game.Log, LogEntry{
		Message: "Bob funded: 10 BTC",
		Txid:    bobTxid,
		Type:    "fund",
	})

	if err := mine(1); err != nil {
		jsonError(w, fmt.Sprintf("mine: %v", err), 500)
		return
	}

	aliceUTXO, err := findUTXO(aliceTxid, alice.P2PKH)
	if err != nil {
		jsonError(w, fmt.Sprintf("find alice utxo: %v", err), 500)
		return
	}
	game.AliceUTXO = aliceUTXO
	game.Alice.Balance = int64(aliceUTXO.Satoshis)

	bobUTXO, err := findUTXO(bobTxid, bob.P2PKH)
	if err != nil {
		jsonError(w, fmt.Sprintf("find bob utxo: %v", err), 500)
		return
	}
	game.BobUTXO = bobUTXO
	game.Bob.Balance = int64(bobUTXO.Satoshis)

	game.AliceBalance = game.Alice.Balance
	game.BobBalance = game.Bob.Balance
	game.Inited = true
	game.Phase = "ready"

	jsonResponse(w, game)
}

func handleState(w http.ResponseWriter, r *http.Request) {
	// R-152: resolve this visitor's game. The package-level singleton is gone,
	// so a handler that forgets this does not compile.
	game := sessionFor(w, r)
	game.mu.Lock()
	defer game.mu.Unlock()
	jsonResponse(w, game)
}

func handleNewRound(w http.ResponseWriter, r *http.Request) {
	// R-152: resolve this visitor's game. The package-level singleton is gone,
	// so a handler that forgets this does not compile.
	game := sessionFor(w, r)
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if !game.Inited {
		jsonError(w, "game not initialized", 400)
		return
	}

	if game.Phase != "ready" && game.Phase != "complete" {
		jsonError(w, "not ready for new round (phase: "+game.Phase+")", 400)
		return
	}

	game.Round++
	game.Threshold = rand.Intn(100) + 1
	game.AliceBet = ""
	game.BobBet = ""
	game.LockingScript = ""
	game.ContractTxid = ""
	game.Phase = "betting"

	game.Log = append(game.Log, LogEntry{
		Message: fmt.Sprintf("Round %d: Threshold = %d", game.Round, game.Threshold),
		Type:    "round",
	})

	jsonResponse(w, game)
}

func handleBet(w http.ResponseWriter, r *http.Request) {
	// R-152: resolve this visitor's game. The package-level singleton is gone,
	// so a handler that forgets this does not compile.
	game := sessionFor(w, r)
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	var req struct {
		Player string `json:"player"`
		Choice string `json:"choice"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "bad request", 400)
		return
	}

	if req.Choice != "over" && req.Choice != "under" {
		jsonError(w, "choice must be 'over' or 'under'", 400)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if game.Phase != "betting" {
		jsonError(w, "not in betting phase", 400)
		return
	}

	switch req.Player {
	case "alice":
		if game.AliceBet != "" {
			jsonError(w, "alice already bet", 400)
			return
		}
		game.AliceBet = req.Choice
		if game.BobBet == "" {
			if req.Choice == "over" {
				game.BobBet = "under"
			} else {
				game.BobBet = "over"
			}
		}
	case "bob":
		if game.BobBet != "" {
			jsonError(w, "bob already bet", 400)
			return
		}
		game.BobBet = req.Choice
		if game.AliceBet == "" {
			if req.Choice == "over" {
				game.AliceBet = "under"
			} else {
				game.AliceBet = "over"
			}
		}
	default:
		jsonError(w, "player must be 'alice' or 'bob'", 400)
		return
	}

	if game.AliceBet != "" && game.BobBet != "" {
		if err := deployContract(game); err != nil {
			jsonError(w, fmt.Sprintf("deploy contract: %v", err), 500)
			return
		}
	}

	jsonResponse(w, game)
}

// deployContract builds and broadcasts the contract funding tx for ONE
// visitor's game (R-152: it used to reach for the package-level singleton).
func deployContract(game *GameState) error {
	scriptHex, _, err := compilePriceBet(game.Lang, game.Alice.PubKeyHex, game.Bob.PubKeyHex, game.Threshold)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	game.LockingScript = scriptHex

	aliceContrib := uint64(contractSats / 2)
	bobContrib := uint64(contractSats) - aliceContrib

	txHex, err := buildFundingTx(game.Alice, game.Bob, game.AliceUTXO, game.BobUTXO, scriptHex, contractSats)
	if err != nil {
		return fmt.Errorf("build funding tx: %w", err)
	}

	txid, err := broadcastTx(txHex)
	if err != nil {
		return fmt.Errorf("broadcast funding tx: %w", err)
	}

	if err := mine(1); err != nil {
		return fmt.Errorf("mine: %w", err)
	}

	game.ContractTxid = txid
	game.ContractVout = 0

	aliceChange := game.AliceUTXO.Satoshis - aliceContrib
	bobChange := game.BobUTXO.Satoshis - bobContrib

	aliceUTXOs, _ := findAllUTXOs(txid, game.Alice.P2PKH)
	if len(aliceUTXOs) > 0 {
		game.AliceUTXO = aliceUTXOs[0]
		aliceChange = aliceUTXOs[0].Satoshis
	}

	bobUTXOs, _ := findAllUTXOs(txid, game.Bob.P2PKH)
	if len(bobUTXOs) > 0 {
		game.BobUTXO = bobUTXOs[0]
		bobChange = bobUTXOs[0].Satoshis
	}

	game.Alice.Balance = int64(aliceChange)
	game.Bob.Balance = int64(bobChange)
	game.AliceBalance = game.Alice.Balance
	game.BobBalance = game.Bob.Balance

	game.Phase = "deployed"

	game.Log = append(game.Log, LogEntry{
		Message: fmt.Sprintf("Round %d: Contract deployed (%d sats)", game.Round, contractSats),
		Txid:    txid,
		Type:    "deploy",
	})

	return nil
}

func handleReveal(w http.ResponseWriter, r *http.Request) {
	// R-152: resolve this visitor's game. The package-level singleton is gone,
	// so a handler that forgets this does not compile.
	game := sessionFor(w, r)
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if game.Phase != "deployed" {
		jsonError(w, "contract not deployed", 400)
		return
	}

	oracle := rand.Intn(100) + 1

	var winner string
	var winnerP2PKH string
	if oracle > game.Threshold {
		if game.AliceBet == "over" {
			winner = "alice"
			winnerP2PKH = game.Alice.P2PKH
		} else {
			winner = "bob"
			winnerP2PKH = game.Bob.P2PKH
		}
	} else {
		if game.AliceBet == "under" {
			winner = "alice"
			winnerP2PKH = game.Alice.P2PKH
		} else {
			winner = "bob"
			winnerP2PKH = game.Bob.P2PKH
		}
	}

	contractUTXO := &UTXO{
		Txid:     game.ContractTxid,
		Vout:     game.ContractVout,
		Satoshis: contractSats,
		Script:   game.LockingScript,
	}

	txHex, err := buildSpendingTx(game.Alice, game.Bob, contractUTXO, winnerP2PKH, contractSats)
	if err != nil {
		jsonError(w, fmt.Sprintf("build spending tx: %v", err), 500)
		return
	}

	spendTxid, err := broadcastTx(txHex)
	if err != nil {
		jsonError(w, fmt.Sprintf("broadcast spending tx: %v", err), 500)
		return
	}

	if err := mine(1); err != nil {
		jsonError(w, fmt.Sprintf("mine: %v", err), 500)
		return
	}

	winnerUTXOs, _ := findAllUTXOs(spendTxid, winnerP2PKH)
	if winner == "alice" {
		if len(winnerUTXOs) > 0 {
			game.Alice.Balance = int64(game.AliceUTXO.Satoshis + winnerUTXOs[0].Satoshis)
		}
	} else {
		if len(winnerUTXOs) > 0 {
			game.Bob.Balance = int64(game.BobUTXO.Satoshis + winnerUTXOs[0].Satoshis)
		}
	}
	game.AliceBalance = game.Alice.Balance
	game.BobBalance = game.Bob.Balance

	result := RoundResult{
		Round:     game.Round,
		Threshold: game.Threshold,
		Oracle:    oracle,
		AliceBet:  game.AliceBet,
		BobBet:    game.BobBet,
		Winner:    winner,
		DeployTx:  game.ContractTxid,
		SpendTx:   spendTxid,
	}
	game.History = append(game.History, result)
	game.Phase = "complete"

	comp := ">"
	if oracle <= game.Threshold {
		comp = "≤"
	}
	game.Log = append(game.Log, LogEntry{
		Message: fmt.Sprintf("Round %d: Oracle=%d %s %d → %s wins!", game.Round, oracle, comp, game.Threshold, strings.ToUpper(winner[:1])+winner[1:]),
		Txid:    spendTxid,
		Type:    "reveal",
	})

	jsonResponse(w, map[string]interface{}{
		"oracle":  oracle,
		"winner":  winner,
		"spendTx": spendTxid,
		"state":   game,
	})
}

// handleLang lets the frontend switch the active source language without
// reinitialising wallets or the regtest state. Accepts POST with body
// { "lang": "<key>" }. Also serves GET to report the current selection and
// the full set of supported languages (useful for populating the UI).
func handleLang(w http.ResponseWriter, r *http.Request) {
	// R-152: resolve this visitor's game. The package-level singleton is gone,
	// so a handler that forgets this does not compile.
	game := sessionFor(w, r)
	switch r.Method {
	case "GET":
		game.mu.Lock()
		defer game.mu.Unlock()
		jsonResponse(w, map[string]interface{}{
			"lang":      normalizeLang(game.Lang),
			"supported": supportedLangs(),
		})
	case "POST":
		var req struct {
			Lang string `json:"lang"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request", 400)
			return
		}
		game.mu.Lock()
		defer game.mu.Unlock()
		game.Lang = normalizeLang(req.Lang)
		jsonResponse(w, map[string]string{"lang": game.Lang})
	default:
		jsonError(w, "GET or POST only", 405)
	}
}

// compileSourceFn is the compile entry point used by handleCompile. It is a
// variable so tests can substitute a stub.
var compileSourceFn = compileSource

// handleCompile is the playground endpoint: it accepts arbitrary Rúnar
// source for any supported input format and returns the compiled locking
// script. The filename's extension drives parser dispatch (".runar.java"
// selects the Java parser, ".runar.ts" the TypeScript parser, and so on).
// No wallet state or regtest connectivity is required, so this path is
// usable as an end-to-end smoke test of the Java language tier.
func handleCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCompileBodyBytes)

	var req struct {
		Source   string `json:"source"`
		Filename string `json:"filename"`
		Lang     string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonError(w, fmt.Sprintf("request body exceeds %d bytes", maxCompileBodyBytes),
				http.StatusRequestEntityTooLarge)
			return
		}
		jsonError(w, "bad request: "+err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.Source) == "" {
		jsonError(w, "source required", 400)
		return
	}

	// If the caller supplies an explicit filename we respect it (that's the
	// canonical way to select a parser). Otherwise we derive one from the
	// lang hint so a minimal client can just send { lang: "java", source }.
	filename := strings.TrimSpace(req.Filename)
	if filename == "" {
		spec, ok := sourceLangs[normalizeLang(req.Lang)]
		if !ok {
			jsonError(w, "unknown lang", 400)
			return
		}
		filename = spec.filename
	}

	// The compiler pipeline is synchronous and has no cancellation hook, so
	// run it on its own goroutine and stop waiting once the deadline passes.
	// The goroutine is left to finish on its own -- the buffered channel means
	// it never blocks -- so a pathological compile still burns one worker, but
	// it no longer holds the client connection or the handler goroutine.
	ctx, cancel := context.WithTimeout(r.Context(), compileTimeout)
	defer cancel()

	type compileResult struct {
		scriptHex string
		scriptAsm string
		anf       *ir.ANFProgram
		err       error
	}
	resultCh := make(chan compileResult, 1)
	go func() {
		hex, asm, anf, err := compileSourceFn([]byte(req.Source), filename)
		resultCh <- compileResult{hex, asm, anf, err}
	}()

	select {
	case <-ctx.Done():
		jsonError(w, fmt.Sprintf("compile exceeded %s", compileTimeout),
			http.StatusServiceUnavailable)
		return
	case res := <-resultCh:
		if res.err != nil {
			jsonError(w, res.err.Error(), 400)
			return
		}
		payload := map[string]any{
			"scriptHex": res.scriptHex,
			"scriptAsm": res.scriptAsm,
			"filename":  filename,
		}
		// R-214: the ANF IR is what makes this a playground rather than a hex
		// printer. Omitted entirely when the pipeline produced none, so a
		// client can tell "no IR" from "empty IR".
		if res.anf != nil {
			payload["anfIr"] = res.anf
		}
		jsonResponse(w, payload)
	}
}

// handleTemplate serves the starter contract for one language.
//
// R-154: the frontend used to carry its own templates and had exactly two of
// the nine — java and ts — with `|| PLAYGROUND_TEMPLATES.java` covering the
// rest. Choosing Ruby and clicking "Load Template" produced Java source, which
// was then sent for compilation as `P2PKH.runar.rb` and rejected. The failure
// looked like the user's mistake.
//
// Seven more string literals in app.js would be the same bug with a longer
// fuse. These bytes come off disk from the per-language PriceBet sources the
// webapp already resolves and compiles for every round, so a template that
// stops compiling is a broken example contract — something the rest of the
// suite already notices — rather than a stale copy nobody reads.
//
// Unlike /api/compile this does NOT fall back to TypeScript for an unknown
// language. `normalizeLang` maps anything unrecognised to "ts", which is a
// sensible default for compiling and would reinstate exactly this bug here:
// handing back a language the caller did not ask for, silently.
func handleTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "" && r.Method != http.MethodGet {
		jsonError(w, "GET only", 405)
		return
	}

	key := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	spec, ok := sourceLangs[key]
	if !ok {
		jsonError(w, fmt.Sprintf("unknown lang %q", key), 400)
		return
	}

	source, err := readContractSource(spec)
	if err != nil {
		jsonError(w, fmt.Sprintf("template unavailable for %s: %v", key, err), 500)
		return
	}

	jsonResponse(w, map[string]any{
		"lang":     key,
		"filename": spec.filename,
		"source":   string(source),
	})
}

// supportedLangs returns the language menu presented to the frontend. The
// order is the canonical presentation order (TS first because it is the
// default and the reference implementation for every fixture).
func supportedLangs() []map[string]string {
	order := []string{"ts", "sol", "move", "go", "rs", "py", "rb", "zig", "java"}
	labels := map[string]string{
		"ts":   "TypeScript",
		"sol":  "Solidity",
		"move": "Move",
		"go":   "Go",
		"rs":   "Rust",
		"py":   "Python",
		"rb":   "Ruby",
		"zig":  "Zig",
		"java": "Java",
	}
	out := make([]map[string]string, 0, len(order))
	for _, k := range order {
		spec, ok := sourceLangs[k]
		if !ok {
			continue
		}
		out = append(out, map[string]string{
			"key":      k,
			"label":    labels[k],
			"filename": spec.filename,
		})
	}
	return out
}
