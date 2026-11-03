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

// bidPaying makes a bid whose continuation carries the prior pot (ExtractAmount
// is 10000 off-chain) plus the bid (N-027).
func bidPaying(c *Auction, sig runar.Sig, bidder runar.PubKey, amount runar.Bigint) {
	defer runar.SetMockContinuationAmount(10000 + amount)()
	c.Bid(sig, bidder, amount)
}

func TestAuction_Bid(t *testing.T) {
	c := newAuction()
	bidder := runar.Bob.PubKey
	bidderSig := runar.SignTestMessage(runar.Bob.PrivKey)
	bidPaying(c, bidderSig, bidder, 200)
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
	bidPaying(newAuction(), bidderSig, runar.Bob.PubKey, 50)
}

// N-027: the bid must be paid into the pot. Carrying the pot forward unpaid
// (continuation = 10000) passes F-024's `>= input` floor but not bid's rule.
func TestAuction_Bid_MustBePaid(t *testing.T) {
	bidderSig := runar.SignTestMessage(runar.Bob.PrivKey)
	for _, continuation := range []int64{10000, 10000 + 200 - 1} {
		func() {
			defer runar.SetMockContinuationAmount(continuation)()
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected assertion failure for continuation %d", continuation)
				}
			}()
			newAuction().Bid(bidderSig, runar.Bob.PubKey, 200)
		}()
	}
}

func TestAuction_MultipleBids(t *testing.T) {
	c := newAuction()
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	charlieSig := runar.SignTestMessage(runar.Charlie.PrivKey)
	bidPaying(c, bobSig, runar.Bob.PubKey, 200)
	bidPaying(c, charlieSig, runar.Charlie.PubKey, 300)
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
