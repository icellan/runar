package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Ledger -- F-352 second witness for the mutable-state shape
// {PubKey, bigint, bigint}.
type Ledger struct {
	runar.StatefulSmartContract
	Holder  runar.PubKey
	Balance runar.Bigint
	Nonce   runar.Bigint
}

func (c *Ledger) Spend(sig runar.Sig, amount runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Holder))
	runar.Assert(amount > 0)
	runar.Assert(amount <= c.Balance)
	c.Balance = c.Balance - amount
	c.Nonce = c.Nonce + 1
}
