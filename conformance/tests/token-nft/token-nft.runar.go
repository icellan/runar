package contract

import "runar"

type SimpleNFT struct {
	runar.StatefulSmartContract
	Owner    runar.PubKey
	TokenId  runar.ByteString `runar:"readonly"`
	Metadata runar.ByteString `runar:"readonly"`
}

func (c *SimpleNFT) Transfer(sig runar.Sig, newOwner runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	c.AddOutput(outputSatoshis, newOwner)
}

func (c *SimpleNFT) Burn(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
}
