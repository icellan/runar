package contract

import "runar"

type Auction struct {
	runar.StatefulSmartContract
	Auctioneer    runar.PubKey `runar:"readonly"`
	HighestBidder runar.PubKey // stateful
	HighestBid    runar.Bigint // stateful
	Deadline      runar.Bigint `runar:"readonly"` // block height deadline
}

// State-mutating: compiler auto-injects checkPreimage + state continuation
func (c *Auction) Bid(bidder runar.PubKey, bidAmount runar.Bigint) {
	// Bid must be higher than current highest
	runar.Assert(bidAmount > c.HighestBid)

	// Auction must not have ended
	runar.Assert(runar.ExtractLocktime(c.TxPreimage) < c.Deadline)

	// Update state
	c.HighestBidder = bidder
	c.HighestBid = bidAmount
}

// Non-mutating: compiler auto-injects checkPreimage only (no state continuation)
func (c *Auction) Close(sig runar.Sig) {
	// Only auctioneer can close
	runar.Assert(runar.CheckSig(sig, c.Auctioneer))

	// Auction must have ended
	runar.Assert(runar.ExtractLocktime(c.TxPreimage) >= c.Deadline)
}
