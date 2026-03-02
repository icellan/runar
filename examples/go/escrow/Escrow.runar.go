package contract

import "runar"

type Escrow struct {
	runar.SmartContract
	Buyer  runar.PubKey `runar:"readonly"`
	Seller runar.PubKey `runar:"readonly"`
	Arbiter runar.PubKey `runar:"readonly"`
}

func (c *Escrow) ReleaseBySeller(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Seller))
}

func (c *Escrow) ReleaseByArbiter(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Arbiter))
}

func (c *Escrow) RefundToBuyer(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Buyer))
}

func (c *Escrow) RefundByArbiter(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Arbiter))
}
