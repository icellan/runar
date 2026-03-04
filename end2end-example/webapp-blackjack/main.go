package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sync"
)

//go:embed static
var staticFS embed.FS

type PlayerSeat struct {
	Name         string   `json:"name"`
	Hand         []Card   `json:"hand"`
	HandValue    int      `json:"handValue"`
	Balance      int64    `json:"balance"`
	Outcome      string   `json:"outcome"`
	IsBlackjack  bool     `json:"isBlackjack"`
	IsBust       bool     `json:"isBust"`
	IsStanding   bool     `json:"isStanding"`
	PubKey       string   `json:"pubKey"`
	Address      string   `json:"address"`
	ContractTxid string   `json:"contractTxid,omitempty"`
	SettleTxid   string   `json:"settleTxid,omitempty"`
}

type DealerState struct {
	Hand       []Card `json:"hand"`
	HandValue  int    `json:"handValue"`
	ShowHidden bool   `json:"showHidden"`
}

func (d DealerState) VisibleHand() []Card {
	if d.ShowHidden || len(d.Hand) == 0 {
		return d.Hand
	}
	return d.Hand[:1]
}

func (d DealerState) VisibleValue() int {
	if d.ShowHidden {
		return d.HandValue
	}
	if len(d.Hand) == 0 {
		return 0
	}
	return CardValue(d.Hand[0].Rank)
}

type LogEntry struct {
	Message string `json:"message"`
	Txid    string `json:"txid,omitempty"`
	Type    string `json:"type"`
}

type AuditData struct {
	RoundId        int              `json:"roundId"`
	DeckCommitment string           `json:"deckCommitment"`
	DeckCommitTxid string           `json:"deckCommitTxid"`
	DeckSalt       string           `json:"deckSalt"`
	DeckOrder      []Card           `json:"deckOrder"`
	DealerHand     []Card           `json:"dealerHand"`
	Players        []AuditPlayer    `json:"players"`
	AuditTxid      string           `json:"auditTxid"`
}

type AuditPlayer struct {
	Name         string `json:"name"`
	Hand         []Card `json:"hand"`
	Outcome      string `json:"outcome"`
	ContractTxid string `json:"contractTxid"`
	SettleTxid   string `json:"settleTxid"`
	RabinSig     string `json:"rabinSig"`
	RabinPadding string `json:"rabinPadding"`
}

type GameState struct {
	mu sync.Mutex

	Phase        string       `json:"phase"`
	NumPlayers   int          `json:"numPlayers"`
	Round        int          `json:"round"`
	Players      []PlayerSeat `json:"players"`
	Dealer       DealerState  `json:"dealer"`
	ActivePlayer int          `json:"activePlayer"`

	House      *Wallet        `json:"-"`
	HouseAddr  string         `json:"houseAddr"`
	HouseBal   int64          `json:"houseBalance"`
	OracleKeys *RabinKeyPair  `json:"-"`
	OraclePub  string         `json:"oraclePubKey"`

	Deck         []Card          `json:"-"`
	DeckCommit   *DeckCommitment `json:"-"`
	DeckPosition int             `json:"-"`
	CommitTxid   string          `json:"deckCommitTxid,omitempty"`

	Contracts  []ContractState `json:"-"`
	PlayerWallets []*Wallet    `json:"-"`
	PlayerUTXOs   []*UTXO      `json:"-"`
	HouseUTXOs    []*UTXO      `json:"-"`

	Log       []LogEntry  `json:"log"`
	LastAudit *AuditData  `json:"-"`
}

var game = &GameState{Phase: "welcome"}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/new-game", handleNewGame)
	mux.HandleFunc("/api/state", handleState)
	mux.HandleFunc("/api/deal", handleDeal)
	mux.HandleFunc("/api/action", handleAction)
	mux.HandleFunc("/api/dealer", handleDealer)
	mux.HandleFunc("/api/audit", handleAudit)
	mux.HandleFunc("/api/new-round", handleNewRound)

	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, _ := staticFS.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Script 21 — Blackjack webapp listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func stateResponse() map[string]any {
	players := make([]map[string]any, len(game.Players))
	for i, p := range game.Players {
		players[i] = map[string]any{
			"name":         p.Name,
			"hand":         p.Hand,
			"handValue":    p.HandValue,
			"balance":      p.Balance,
			"outcome":      p.Outcome,
			"isBlackjack":  p.IsBlackjack,
			"isBust":       p.IsBust,
			"isStanding":   p.IsStanding,
			"pubKey":       p.PubKey,
			"address":      p.Address,
			"contractTxid": p.ContractTxid,
			"settleTxid":   p.SettleTxid,
		}
	}

	dealer := map[string]any{
		"hand":       game.Dealer.VisibleHand(),
		"handValue":  game.Dealer.VisibleValue(),
		"showHidden": game.Dealer.ShowHidden,
	}

	return map[string]any{
		"phase":          game.Phase,
		"numPlayers":     game.NumPlayers,
		"round":          game.Round,
		"players":        players,
		"dealer":         dealer,
		"activePlayer":   game.ActivePlayer,
		"houseAddr":      game.HouseAddr,
		"houseBalance":   game.HouseBal,
		"oraclePubKey":   game.OraclePub,
		"deckCommitHash": commitHash(),
		"deckCommitTxid": game.CommitTxid,
		"log":            game.Log,
	}
}

func commitHash() string {
	if game.DeckCommit != nil {
		return game.DeckCommit.Hash
	}
	return ""
}

func handleNewGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	var req struct {
		NumPlayers int `json:"numPlayers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "bad request", 400)
		return
	}
	if req.NumPlayers < 1 || req.NumPlayers > 7 {
		jsonError(w, "numPlayers must be 1-7", 400)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	game.Phase = "setup"
	game.NumPlayers = req.NumPlayers
	game.Round = 0
	game.Log = nil
	game.LastAudit = nil

	house, err := newWallet()
	if err != nil {
		jsonError(w, fmt.Sprintf("create house wallet: %v", err), 500)
		return
	}
	game.House = house
	game.HouseAddr = house.Address

	houseTxid, err := fundWallet(house.Address, 10.0)
	if err != nil {
		jsonError(w, fmt.Sprintf("fund house: %v", err), 500)
		return
	}
	game.Log = append(game.Log, LogEntry{Message: "House funded: 10 BSV", Txid: houseTxid, Type: "fund"})

	game.PlayerWallets = make([]*Wallet, req.NumPlayers)
	game.PlayerUTXOs = make([]*UTXO, req.NumPlayers)
	game.Players = make([]PlayerSeat, req.NumPlayers)

	for i := 0; i < req.NumPlayers; i++ {
		pw, err := newWallet()
		if err != nil {
			jsonError(w, fmt.Sprintf("create player %d wallet: %v", i+1, err), 500)
			return
		}
		game.PlayerWallets[i] = pw

		txid, err := fundWallet(pw.Address, 1.0)
		if err != nil {
			jsonError(w, fmt.Sprintf("fund player %d: %v", i+1, err), 500)
			return
		}

		game.Players[i] = PlayerSeat{
			Name:    fmt.Sprintf("Player %d", i+1),
			PubKey:  pw.PubKeyHex,
			Address: pw.Address,
		}

		game.Log = append(game.Log, LogEntry{
			Message: fmt.Sprintf("%s funded: 1 BSV", game.Players[i].Name),
			Txid:    txid,
			Type:    "fund",
		})
	}

	if err := mine(1); err != nil {
		jsonError(w, fmt.Sprintf("mine: %v", err), 500)
		return
	}

	houseUTXO, err := findUTXO(houseTxid, house.P2PKH)
	if err != nil {
		jsonError(w, fmt.Sprintf("find house utxo: %v", err), 500)
		return
	}
	game.House.Balance = int64(houseUTXO.Satoshis)
	game.HouseBal = game.House.Balance
	game.HouseUTXOs = []*UTXO{houseUTXO}

	for i := 0; i < req.NumPlayers; i++ {
		fundTxid := game.Log[i+1].Txid
		utxo, err := findUTXO(fundTxid, game.PlayerWallets[i].P2PKH)
		if err != nil {
			jsonError(w, fmt.Sprintf("find player %d utxo: %v", i+1, err), 500)
			return
		}
		game.PlayerUTXOs[i] = utxo
		game.PlayerWallets[i].Balance = int64(utxo.Satoshis)
		game.Players[i].Balance = game.PlayerWallets[i].Balance
	}

	oracleKeys, err := GenerateRabinKeyPair()
	if err != nil {
		jsonError(w, fmt.Sprintf("generate oracle keys: %v", err), 500)
		return
	}
	game.OracleKeys = oracleKeys
	game.OraclePub = oracleKeys.N.String()

	game.Phase = "ready"
	game.Log = append(game.Log, LogEntry{Message: "Game initialized. Ready to deal.", Type: "info"})

	jsonResponse(w, stateResponse())
}

func handleState(w http.ResponseWriter, _ *http.Request) {
	game.mu.Lock()
	defer game.mu.Unlock()
	jsonResponse(w, stateResponse())
}

func handleDeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if game.Phase != "ready" {
		jsonError(w, "not ready to deal (phase: "+game.Phase+")", 400)
		return
	}

	game.Round++
	game.Deck = NewShuffledDeck()
	game.DeckPosition = 0

	commit, err := CommitDeck(game.Deck)
	if err != nil {
		jsonError(w, fmt.Sprintf("commit deck: %v", err), 500)
		return
	}
	game.DeckCommit = commit

	if len(game.HouseUTXOs) > 0 {
		commitTxHex, err := buildOpReturnTx(game.House, game.HouseUTXOs[0], []byte(commit.Hash))
		if err != nil {
			jsonError(w, fmt.Sprintf("build commit tx: %v", err), 500)
			return
		}
		commitTxid, err := broadcastTx(commitTxHex)
		if err != nil {
			jsonError(w, fmt.Sprintf("broadcast commit: %v", err), 500)
			return
		}
		game.CommitTxid = commitTxid
		game.Log = append(game.Log, LogEntry{
			Message: fmt.Sprintf("Round %d: Deck committed (SHA-256)", game.Round),
			Txid:    commitTxid,
			Type:    "commit",
		})

		changeUTXOs, _ := findAllUTXOs(commitTxid, game.House.P2PKH)
		if len(changeUTXOs) > 0 {
			game.HouseUTXOs = changeUTXOs
			game.House.Balance = int64(changeUTXOs[0].Satoshis)
			game.HouseBal = game.House.Balance
		}
	}

	game.Contracts = make([]ContractState, game.NumPlayers)
	roundId := int64(game.Round * 1000)

	for i := 0; i < game.NumPlayers; i++ {
		if game.PlayerUTXOs[i] == nil || len(game.HouseUTXOs) == 0 {
			jsonError(w, fmt.Sprintf("no UTXO for player %d or house", i+1), 500)
			return
		}

		cs, newPlayerUTXO, newHouseUTXO, err := deployPlayerContract(
			game.PlayerWallets[i], game.PlayerUTXOs[i],
			game.House, game.HouseUTXOs[0],
			game.OracleKeys.N, roundId+int64(i),
		)
		if err != nil {
			jsonError(w, fmt.Sprintf("deploy contract for player %d: %v", i+1, err), 500)
			return
		}

		cs.PlayerIndex = i
		game.Contracts[i] = *cs

		if newPlayerUTXO != nil {
			game.PlayerUTXOs[i] = newPlayerUTXO
			game.PlayerWallets[i].Balance = int64(newPlayerUTXO.Satoshis)
		} else {
			game.PlayerUTXOs[i] = nil
			game.PlayerWallets[i].Balance -= betSats
		}
		game.Players[i].Balance = game.PlayerWallets[i].Balance
		game.Players[i].ContractTxid = cs.ContractTxid

		if newHouseUTXO != nil {
			game.HouseUTXOs = []*UTXO{newHouseUTXO}
			game.House.Balance = int64(newHouseUTXO.Satoshis)
		} else {
			if len(game.HouseUTXOs) > 1 {
				game.HouseUTXOs = game.HouseUTXOs[1:]
			} else {
				game.HouseUTXOs = nil
			}
			game.House.Balance -= betSats
		}
		game.HouseBal = game.House.Balance

		game.Log = append(game.Log, LogEntry{
			Message: fmt.Sprintf("Round %d: %s contract deployed (%d sats)", game.Round, game.Players[i].Name, contractSats),
			Txid:    cs.ContractTxid,
			Type:    "deploy",
		})
	}

	if err := mine(1); err != nil {
		jsonError(w, fmt.Sprintf("mine: %v", err), 500)
		return
	}

	for i := 0; i < game.NumPlayers; i++ {
		game.Players[i].Hand = []Card{game.Deck[game.DeckPosition], game.Deck[game.DeckPosition+1]}
		game.DeckPosition += 2
		game.Players[i].HandValue = HandValue(game.Players[i].Hand)
		game.Players[i].IsBlackjack = IsBlackjack(game.Players[i].Hand)
		game.Players[i].Outcome = ""
		game.Players[i].IsBust = false
		game.Players[i].IsStanding = false
		game.Players[i].SettleTxid = ""
	}

	game.Dealer = DealerState{
		Hand:       []Card{game.Deck[game.DeckPosition], game.Deck[game.DeckPosition+1]},
		HandValue:  HandValue([]Card{game.Deck[game.DeckPosition], game.Deck[game.DeckPosition+1]}),
		ShowHidden: false,
	}
	game.DeckPosition += 2

	game.ActivePlayer = findNextActivePlayer(-1)
	if game.ActivePlayer == -1 {
		game.Phase = "dealer-turn"
	} else {
		game.Phase = "player-turns"
	}

	game.Log = append(game.Log, LogEntry{
		Message: fmt.Sprintf("Round %d: Cards dealt to %d player(s)", game.Round, game.NumPlayers),
		Type:    "deal",
	})

	jsonResponse(w, stateResponse())
}

func findNextActivePlayer(current int) int {
	for i := current + 1; i < game.NumPlayers; i++ {
		if !game.Players[i].IsBlackjack && !game.Players[i].IsBust && !game.Players[i].IsStanding {
			return i
		}
	}
	return -1
}

func handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	var req struct {
		Player int    `json:"player"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "bad request", 400)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if game.Phase != "player-turns" {
		jsonError(w, "not in player-turns phase", 400)
		return
	}

	if req.Player != game.ActivePlayer {
		jsonError(w, fmt.Sprintf("not player %d's turn (active: %d)", req.Player, game.ActivePlayer), 400)
		return
	}

	p := &game.Players[req.Player]

	switch req.Action {
	case "hit":
		if game.DeckPosition >= len(game.Deck) {
			jsonError(w, "deck exhausted", 500)
			return
		}
		p.Hand = append(p.Hand, game.Deck[game.DeckPosition])
		game.DeckPosition++
		p.HandValue = HandValue(p.Hand)
		p.IsBust = IsBust(p.Hand)

		if p.IsBust {
			game.Log = append(game.Log, LogEntry{
				Message: fmt.Sprintf("%s busts with %d", p.Name, p.HandValue),
				Type:    "action",
			})
		}

	case "stand":
		p.IsStanding = true
		game.Log = append(game.Log, LogEntry{
			Message: fmt.Sprintf("%s stands with %d", p.Name, p.HandValue),
			Type:    "action",
		})

	default:
		jsonError(w, "action must be 'hit' or 'stand'", 400)
		return
	}

	if p.IsBust || p.IsStanding {
		game.ActivePlayer = findNextActivePlayer(game.ActivePlayer)
		if game.ActivePlayer == -1 {
			game.Phase = "dealer-turn"
		}
	}

	jsonResponse(w, stateResponse())
}

func handleDealer(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if game.Phase != "dealer-turn" {
		jsonError(w, "not dealer's turn (phase: "+game.Phase+")", 400)
		return
	}

	allBusted := true
	for _, p := range game.Players {
		if !p.IsBust {
			allBusted = false
			break
		}
	}

	if !allBusted {
		for DealerShouldHit(game.Dealer.Hand) {
			if game.DeckPosition >= len(game.Deck) {
				break
			}
			game.Dealer.Hand = append(game.Dealer.Hand, game.Deck[game.DeckPosition])
			game.DeckPosition++
		}
	}

	game.Dealer.HandValue = HandValue(game.Dealer.Hand)
	game.Dealer.ShowHidden = true

	dealerBJ := IsBlackjack(game.Dealer.Hand)

	game.Log = append(game.Log, LogEntry{
		Message: fmt.Sprintf("Dealer reveals: %d", game.Dealer.HandValue),
		Type:    "dealer",
	})

	roundId := int64(game.Round * 1000)

	for i := 0; i < game.NumPlayers; i++ {
		p := &game.Players[i]
		outcome := CompareHands(p.HandValue, game.Dealer.HandValue, p.IsBlackjack, dealerBJ)
		p.Outcome = outcome

		cs := &game.Contracts[i]
		playerRoundId := roundId + int64(i)

		switch outcome {
		case "win", "blackjack":
			winOutcome, rabinSig, err := FindSignableOutcome(playerRoundId+1, game.OracleKeys)
			if err != nil {
				game.Log = append(game.Log, LogEntry{
					Message: fmt.Sprintf("%s: oracle signing failed: %v", p.Name, err),
					Type:    "error",
				})
				continue
			}

			txid, err := settlePlayerWin(cs, game.PlayerWallets[i], game.House, winOutcome, rabinSig)
			if err != nil {
				game.Log = append(game.Log, LogEntry{
					Message: fmt.Sprintf("%s: settle failed: %v", p.Name, err),
					Type:    "error",
				})
				continue
			}

			p.SettleTxid = txid
			cs.Outcome = outcome
			game.PlayerWallets[i].Balance += contractSats
			p.Balance = game.PlayerWallets[i].Balance

			game.Log = append(game.Log, LogEntry{
				Message: fmt.Sprintf("%s wins! +%d sats", p.Name, contractSats),
				Txid:    txid,
				Type:    "settle",
			})

		case "lose":
			loseOutcome, rabinSig, err := FindSignableOutcome(playerRoundId, game.OracleKeys)
			if err != nil {
				game.Log = append(game.Log, LogEntry{
					Message: fmt.Sprintf("%s: oracle signing failed: %v", p.Name, err),
					Type:    "error",
				})
				continue
			}

			txid, err := settleHouseWin(cs, game.PlayerWallets[i], game.House, loseOutcome, rabinSig)
			if err != nil {
				game.Log = append(game.Log, LogEntry{
					Message: fmt.Sprintf("%s: settle failed: %v", p.Name, err),
					Type:    "error",
				})
				continue
			}

			p.SettleTxid = txid
			cs.Outcome = outcome
			game.House.Balance += contractSats
			game.HouseBal = game.House.Balance

			game.Log = append(game.Log, LogEntry{
				Message: fmt.Sprintf("%s loses. House takes %d sats", p.Name, contractSats),
				Txid:    txid,
				Type:    "settle",
			})

		case "push":
			txid, err := settlePush(cs, game.PlayerWallets[i], game.House)
			if err != nil {
				game.Log = append(game.Log, LogEntry{
					Message: fmt.Sprintf("%s: cancel failed: %v", p.Name, err),
					Type:    "error",
				})
				continue
			}

			p.SettleTxid = txid
			cs.Outcome = outcome
			game.PlayerWallets[i].Balance += betSats
			p.Balance = game.PlayerWallets[i].Balance
			game.House.Balance += betSats
			game.HouseBal = game.House.Balance

			game.Log = append(game.Log, LogEntry{
				Message: fmt.Sprintf("%s pushes. Bets returned.", p.Name),
				Txid:    txid,
				Type:    "settle",
			})
		}
	}

	if err := mine(1); err != nil {
		game.Log = append(game.Log, LogEntry{
			Message: fmt.Sprintf("Mine error: %v", err),
			Type:    "error",
		})
	}

	for i := 0; i < game.NumPlayers; i++ {
		if game.Players[i].SettleTxid != "" {
			utxos, _ := findAllUTXOs(game.Players[i].SettleTxid, game.PlayerWallets[i].P2PKH)
			if len(utxos) > 0 {
				game.PlayerUTXOs[i] = utxos[0]
				game.PlayerWallets[i].Balance = int64(utxos[0].Satoshis)
				if game.PlayerUTXOs[i] != nil && game.Players[i].Outcome == "push" {
					old := game.PlayerUTXOs[i]
					game.PlayerWallets[i].Balance = int64(old.Satoshis)
				}
				game.Players[i].Balance = game.PlayerWallets[i].Balance
			}

			houseUtxos, _ := findAllUTXOs(game.Players[i].SettleTxid, game.House.P2PKH)
			if len(houseUtxos) > 0 {
				game.HouseUTXOs = append(game.HouseUTXOs, houseUtxos...)
				total := int64(0)
				for _, u := range game.HouseUTXOs {
					total += int64(u.Satoshis)
				}
				game.House.Balance = total
				game.HouseBal = game.House.Balance
			}
		}
	}

	game.LastAudit = buildAuditData()
	game.Phase = "settlement"

	jsonResponse(w, stateResponse())
}

func buildAuditData() *AuditData {
	audit := &AuditData{
		RoundId:        game.Round,
		DealerHand:     game.Dealer.Hand,
	}

	if game.DeckCommit != nil {
		audit.DeckCommitment = game.DeckCommit.Hash
		audit.DeckSalt = game.DeckCommit.Salt
	}
	audit.DeckCommitTxid = game.CommitTxid
	audit.DeckOrder = game.Deck

	for i, p := range game.Players {
		cs := game.Contracts[i]
		audit.Players = append(audit.Players, AuditPlayer{
			Name:         p.Name,
			Hand:         p.Hand,
			Outcome:      p.Outcome,
			ContractTxid: cs.ContractTxid,
			SettleTxid:   cs.SettleTxid,
			RabinSig:     cs.RabinSigHex,
			RabinPadding: cs.RabinPadHex,
		})
	}

	return audit
}

func handleAudit(w http.ResponseWriter, _ *http.Request) {
	game.mu.Lock()
	defer game.mu.Unlock()

	if game.LastAudit == nil {
		jsonError(w, "no audit data available", 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=round-%d-audit.json", game.LastAudit.RoundId))
	json.NewEncoder(w).Encode(game.LastAudit)
}

func handleNewRound(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", 405)
		return
	}

	game.mu.Lock()
	defer game.mu.Unlock()

	if game.Phase != "settlement" {
		jsonError(w, "round not complete (phase: "+game.Phase+")", 400)
		return
	}

	for i := range game.Players {
		game.Players[i].Hand = nil
		game.Players[i].HandValue = 0
		game.Players[i].Outcome = ""
		game.Players[i].IsBlackjack = false
		game.Players[i].IsBust = false
		game.Players[i].IsStanding = false
		game.Players[i].ContractTxid = ""
		game.Players[i].SettleTxid = ""
	}

	game.Dealer = DealerState{}
	game.ActivePlayer = 0
	game.Contracts = nil
	game.DeckCommit = nil
	game.CommitTxid = ""
	game.Phase = "ready"

	game.Log = append(game.Log, LogEntry{
		Message: "New round ready.",
		Type:    "info",
	})

	jsonResponse(w, stateResponse())
}
