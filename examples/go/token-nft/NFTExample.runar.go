package contract

import "runar"

type SimpleNFT struct {
	runar.StatefulSmartContract
	Owner    runar.PubKey     // stateful
	TokenId  runar.ByteString `runar:"readonly"` // immutable: unique token identifier
	Metadata runar.ByteString `runar:"readonly"` // immutable: token metadata URI/hash
}

func (c *SimpleNFT) Transfer(sig runar.Sig, newOwner runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	// AddOutput(satoshis, owner) -- single mutable prop
	c.AddOutput(outputSatoshis, newOwner)
}

func (c *SimpleNFT) Burn(sig runar.Sig) {
	// Only owner can burn
	runar.Assert(runar.CheckSig(sig, c.Owner))
	// No AddOutput and no state mutation = token destroyed
}
