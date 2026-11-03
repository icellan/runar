package contract

import runar "github.com/icellan/runar/packages/runar-go"

// OwnerBox -- F-352 second witness for the mutable-state shape {PubKey}.
type OwnerBox struct {
	runar.StatefulSmartContract
	Owner runar.PubKey
}

func (c *OwnerBox) Rotate(sig runar.Sig, newOwner runar.PubKey) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	c.Owner = newOwner
}
