package contract

import "runar"

type FungibleToken struct {
	runar.StatefulSmartContract
	Owner   runar.PubKey     // stateful: current token owner
	Balance runar.Bigint     // stateful: token balance in this UTXO
	TokenId runar.ByteString `runar:"readonly"` // immutable: token identifier
}

// Split: 1 input -> 2 outputs (recipient + change)
func (c *FungibleToken) Transfer(sig runar.Sig, to runar.PubKey, amount runar.Bigint, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(amount > 0)
	runar.Assert(amount <= c.Balance)

	// AddOutput(satoshis, owner, balance) -- args match mutable props in order
	c.AddOutput(outputSatoshis, to, amount)
	c.AddOutput(outputSatoshis, c.Owner, c.Balance-amount)
}

// Simple send: 1 input -> 1 output, full balance
func (c *FungibleToken) Send(sig runar.Sig, to runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))

	c.AddOutput(outputSatoshis, to, c.Balance)
}

// Merge: N inputs -> 1 output (each input calls this independently)
func (c *FungibleToken) Merge(sig runar.Sig, totalBalance runar.Bigint, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(totalBalance >= c.Balance)

	c.AddOutput(outputSatoshis, c.Owner, totalBalance)
}
