package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

type Suit int

const (
	Spades   Suit = 0
	Hearts   Suit = 1
	Diamonds Suit = 2
	Clubs    Suit = 3
)

func (s Suit) String() string {
	switch s {
	case Spades:
		return "spades"
	case Hearts:
		return "hearts"
	case Diamonds:
		return "diamonds"
	case Clubs:
		return "clubs"
	default:
		return "unknown"
	}
}

func (s Suit) Symbol() string {
	switch s {
	case Spades:
		return "\u2660"
	case Hearts:
		return "\u2665"
	case Diamonds:
		return "\u2666"
	case Clubs:
		return "\u2663"
	default:
		return "?"
	}
}

type Card struct {
	Suit Suit `json:"suit"`
	Rank int  `json:"rank"`
}

func (c Card) RankName() string {
	switch c.Rank {
	case 1:
		return "A"
	case 11:
		return "J"
	case 12:
		return "Q"
	case 13:
		return "K"
	default:
		return fmt.Sprintf("%d", c.Rank)
	}
}

func (c Card) String() string {
	return c.RankName() + c.Suit.Symbol()
}

func NewDeck() []Card {
	deck := make([]Card, 0, 52)
	for s := Suit(0); s <= 3; s++ {
		for r := 1; r <= 13; r++ {
			deck = append(deck, Card{Suit: s, Rank: r})
		}
	}
	return deck
}

func ShuffleDeck(deck []Card) {
	for i := len(deck) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		jj := int(j.Int64())
		deck[i], deck[jj] = deck[jj], deck[i]
	}
}

func NewShuffledDeck() []Card {
	deck := NewDeck()
	ShuffleDeck(deck)
	return deck
}

type DeckCommitment struct {
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	DeckStr string `json:"deckStr"`
}

func CommitDeck(deck []Card) (*DeckCommitment, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, err
	}
	salt := hex.EncodeToString(saltBytes)

	deckStr := ""
	for i, c := range deck {
		if i > 0 {
			deckStr += ","
		}
		deckStr += fmt.Sprintf("%d:%d", c.Rank, int(c.Suit))
	}

	data := salt + "|" + deckStr
	hash := sha256.Sum256([]byte(data))

	return &DeckCommitment{
		Salt:    salt,
		Hash:    hex.EncodeToString(hash[:]),
		DeckStr: deckStr,
	}, nil
}

func VerifyDeckCommitment(commitment *DeckCommitment) bool {
	data := commitment.Salt + "|" + commitment.DeckStr
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]) == commitment.Hash
}

func CardValue(rank int) int {
	if rank >= 10 {
		return 10
	}
	if rank == 1 {
		return 11
	}
	return rank
}
