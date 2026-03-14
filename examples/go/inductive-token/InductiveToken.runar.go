package contract

import runar "github.com/icellan/runar/packages/runar-go"

type InductiveToken struct {
	runar.InductiveSmartContract
	Owner   runar.PubKey
	Balance runar.Bigint
	TokenId runar.ByteString `runar:"readonly"`
}

func (c *InductiveToken) Transfer(sig runar.Sig, to runar.PubKey, amount runar.Bigint, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(amount > 0)
	runar.Assert(amount <= c.Balance)

	c.AddOutput(outputSatoshis, to, amount)
	c.AddOutput(outputSatoshis, c.Owner, c.Balance-amount)
}

func (c *InductiveToken) Send(sig runar.Sig, to runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))

	c.AddOutput(outputSatoshis, to, c.Balance)
}
