package contract

import "runar"

type FungibleToken struct {
	runar.StatefulSmartContract
	Owner        runar.PubKey
	Balance      runar.Bigint
	MergeBalance runar.Bigint
	TokenId      runar.ByteString `runar:"readonly"`
}

func (c *FungibleToken) Transfer(sig runar.Sig, to runar.PubKey, amount runar.Bigint, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	totalBalance := c.Balance + c.MergeBalance
	runar.Assert(amount > 0)
	runar.Assert(amount <= totalBalance)
	c.AddOutput(outputSatoshis, to, amount, 0)
	if amount < totalBalance {
		c.AddOutput(outputSatoshis, c.Owner, totalBalance-amount, 0)
	}
}

func (c *FungibleToken) Send(sig runar.Sig, to runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	c.AddOutput(outputSatoshis, to, c.Balance+c.MergeBalance, 0)
}

func (c *FungibleToken) Merge(sig runar.Sig, otherBalance runar.Bigint, allPrevouts runar.ByteString, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	runar.Assert(otherBalance >= 0)
	runar.Assert(runar.Hash256(allPrevouts) == runar.ExtractHashPrevouts(c.TxPreimage))
	myOutpoint := runar.ExtractOutpoint(c.TxPreimage)
	firstOutpoint := runar.Substr(allPrevouts, 0, 36)
	myBalance := c.Balance + c.MergeBalance
	if myOutpoint == firstOutpoint {
		c.AddOutput(outputSatoshis, c.Owner, myBalance, otherBalance)
	} else {
		c.AddOutput(outputSatoshis, c.Owner, otherBalance, myBalance)
	}
}
