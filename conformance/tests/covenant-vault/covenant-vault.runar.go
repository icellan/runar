package contract

import "runar"

type CovenantVault struct {
	runar.SmartContract
	Owner     runar.PubKey `runar:"readonly"`
	Recipient runar.Addr   `runar:"readonly"`
	MinAmount runar.Bigint `runar:"readonly"`
}

func (c *CovenantVault) Spend(sig runar.Sig, txPreimage runar.SigHashPreimage) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(runar.CheckPreimage(txPreimage))
	p2pkhScript := runar.Cat(runar.Cat("1976a914", c.Recipient), "88ac")
	expectedOutput := runar.Cat(runar.Num2Bin(c.MinAmount, 8), p2pkhScript)
	runar.Assert(runar.Hash256(expectedOutput) == runar.ExtractOutputHash(txPreimage))
}
