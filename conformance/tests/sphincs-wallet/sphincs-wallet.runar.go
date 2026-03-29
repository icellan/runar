package contract

import "runar"

type SPHINCSWallet struct {
	runar.SmartContract
	EcdsaPubKeyHash  runar.Addr       `runar:"readonly"`
	SlhdsaPubKeyHash runar.ByteString `runar:"readonly"`
}

func (c *SPHINCSWallet) Spend(slhdsaSig runar.ByteString, slhdsaPubKey runar.ByteString, sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.EcdsaPubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))

	runar.Assert(runar.Hash160(slhdsaPubKey) == c.SlhdsaPubKeyHash)
	runar.Assert(runar.VerifySLHDSA_SHA2_128s(sig, slhdsaSig, slhdsaPubKey))
}
