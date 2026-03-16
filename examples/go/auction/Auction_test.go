package contract

import (
	runar "github.com/icellan/runar/packages/runar-go"
	"testing"
)

func newAuction() *Auction {
	return &Auction{
		Auctioneer:    runar.Alice.PubKey,
		HighestBidder: runar.Bob.PubKey,
		HighestBid:    100,
		Deadline:      1000,
	}
}

func TestAuction_Bid(t *testing.T) {
	c := newAuction()
	bidder := runar.Bob.PubKey
	bidderSig := runar.SignTestMessage(runar.Bob.PrivKey)
	c.Bid(bidderSig, bidder, 200)
	if c.HighestBid != 200 {
		t.Errorf("expected HighestBid=200, got %d", c.HighestBid)
	}
}

func TestAuction_Bid_MustBeHigher(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	bidderSig := runar.SignTestMessage(runar.Bob.PrivKey)
	newAuction().Bid(bidderSig, runar.Bob.PubKey, 50)
}

func TestAuction_MultipleBids(t *testing.T) {
	c := newAuction()
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	charlieSig := runar.SignTestMessage(runar.Charlie.PrivKey)
	c.Bid(bobSig, runar.Bob.PubKey, 200)
	c.Bid(charlieSig, runar.Charlie.PubKey, 300)
	if c.HighestBid != 300 {
		t.Errorf("expected HighestBid=300, got %d", c.HighestBid)
	}
}

func TestAuction_Close(t *testing.T) {
	c := newAuction()
	c.Deadline = 0
	auctioneerSig := runar.SignTestMessage(runar.Alice.PrivKey)
	c.Close(auctioneerSig)
}

func TestAuction_Close_BeforeDeadline_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	auctioneerSig := runar.SignTestMessage(runar.Alice.PrivKey)
	newAuction().Close(auctioneerSig)
}

func TestAuction_Compile(t *testing.T) {
	if err := runar.CompileCheck("Auction.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
