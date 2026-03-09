package contract

import (
	runar "github.com/icellan/runar/packages/runar-go"
	"testing"
)

func newAuction() *Auction {
	return &Auction{
		Auctioneer:    runar.MockPubKey(),
		HighestBidder: runar.PubKey("initial_bidder_placeholder_33b!"),
		HighestBid:    100,
		Deadline:      1000,
	}
}

func TestAuction_Bid(t *testing.T) {
	c := newAuction()
	bidder := runar.PubKey("new_bidder_placeholder_33bytes!")
	c.Bid(runar.MockSig(), bidder, 200)
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
	newAuction().Bid(runar.MockSig(), runar.MockPubKey(), 50)
}

func TestAuction_MultipleBids(t *testing.T) {
	c := newAuction()
	c.Bid(runar.MockSig(), runar.PubKey("bidder1_33bytes_placeholder_____"), 200)
	c.Bid(runar.MockSig(), runar.PubKey("bidder2_33bytes_placeholder_____"), 300)
	if c.HighestBid != 300 {
		t.Errorf("expected HighestBid=300, got %d", c.HighestBid)
	}
}

func TestAuction_Close(t *testing.T) {
	c := newAuction()
	c.Deadline = 0
	c.Close(runar.MockSig())
}

func TestAuction_Close_BeforeDeadline_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	newAuction().Close(runar.MockSig())
}

func TestAuction_Compile(t *testing.T) {
	if err := runar.CompileCheck("Auction.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
