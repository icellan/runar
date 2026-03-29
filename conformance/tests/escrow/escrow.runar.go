package contract

import "runar"

type Escrow struct {
	runar.SmartContract
	Buyer   runar.PubKey `runar:"readonly"`
	Seller  runar.PubKey `runar:"readonly"`
	Arbiter runar.PubKey `runar:"readonly"`
}

func (c *Escrow) Release(sellerSig runar.Sig, arbiterSig runar.Sig) {
	runar.Assert(runar.CheckSig(sellerSig, c.Seller))
	runar.Assert(runar.CheckSig(arbiterSig, c.Arbiter))
}

func (c *Escrow) Refund(buyerSig runar.Sig, arbiterSig runar.Sig) {
	runar.Assert(runar.CheckSig(buyerSig, c.Buyer))
	runar.Assert(runar.CheckSig(arbiterSig, c.Arbiter))
}
