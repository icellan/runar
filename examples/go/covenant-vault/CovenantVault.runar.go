package contract

import "runar"

type CovenantVault struct {
	runar.SmartContract
	Owner     runar.PubKey `runar:"readonly"`
	Recipient runar.Addr   `runar:"readonly"`
	MinAmount runar.Bigint `runar:"readonly"`
}

func (c *CovenantVault) Spend(sig runar.Sig, amount runar.Bigint, txPreimage runar.SigHashPreimage) {
	// Owner must authorize
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(runar.CheckPreimage(txPreimage))

	// Enforce minimum output amount (covenant rule)
	runar.Assert(amount >= c.MinAmount)
}
