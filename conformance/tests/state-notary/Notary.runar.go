package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Notary -- F-352 second witness for the mutable-state shape
// {ByteString, PubKey, bigint}, with the PubKey declared first.
type Notary struct {
	runar.StatefulSmartContract
	Signer runar.PubKey
	Note   runar.ByteString
	Seq    runar.Bigint
}

func (c *Notary) Notarize(sig runar.Sig, nextNote runar.ByteString) {
	runar.Assert(runar.CheckSig(sig, c.Signer))
	c.Note = nextNote
	c.Seq = c.Seq + 1
}
