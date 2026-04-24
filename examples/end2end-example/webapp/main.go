package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
)

const contractSats = 20000

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

var game = &GameState{Phase: "init"}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/init", handleInit)
	mux.HandleFunc("/api/state", handleState)
	mux.HandleFunc("/api/round/new", handleNewRound)
	mux.HandleFunc("/api/round/bet", handleBet)
	mux.HandleFunc("/api/round/reveal", handleReveal)
	mux.HandleFunc("/api/compile", handleCompile)
	mux.HandleFunc("/api/lang", handleLang)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "static/index.html")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("PriceBet webapp listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
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
	game.mu.Lock()
	defer game.mu.Unlock()
	jsonResponse(w, game)
}

func handleNewRound(w http.ResponseWriter, r *http.Request) {
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
		if err := deployContract(); err != nil {
			jsonError(w, fmt.Sprintf("deploy contract: %v", err), 500)
			return
		}
	}

	jsonResponse(w, game)
}

func deployContract() error {
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

	var req struct {
		Source   string `json:"source"`
		Filename string `json:"filename"`
		Lang     string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	scriptHex, scriptAsm, err := compileSource([]byte(req.Source), filename)
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}

	jsonResponse(w, map[string]string{
		"scriptHex": scriptHex,
		"scriptAsm": scriptAsm,
		"filename":  filename,
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
