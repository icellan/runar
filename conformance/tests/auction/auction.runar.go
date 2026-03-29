package contract

import "runar"

type Auction struct {
	runar.StatefulSmartContract
	Auctioneer    runar.PubKey `runar:"readonly"`
	HighestBidder runar.PubKey
	HighestBid    runar.Bigint
	Deadline      runar.Bigint `runar:"readonly"`
}

func (c *Auction) Bid(sig runar.Sig, bidder runar.PubKey, bidAmount runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, bidder))
	runar.Assert(bidAmount > c.HighestBid)
	runar.Assert(runar.ExtractLocktime(c.TxPreimage) < c.Deadline)
	c.HighestBidder = bidder
	c.HighestBid = bidAmount
}

func (c *Auction) Close(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Auctioneer))
	runar.Assert(runar.ExtractLocktime(c.TxPreimage) >= c.Deadline)
}
