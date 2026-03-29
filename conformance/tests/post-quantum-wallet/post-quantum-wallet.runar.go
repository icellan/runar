package contract

import "runar"

type PostQuantumWallet struct {
	runar.SmartContract
	EcdsaPubKeyHash runar.Addr       `runar:"readonly"`
	WotsPubKeyHash  runar.ByteString `runar:"readonly"`
}

func (c *PostQuantumWallet) Spend(wotsSig runar.ByteString, wotsPubKey runar.ByteString, sig runar.Sig, pubKey runar.PubKey) {
	// Step 1: Verify ECDSA
	runar.Assert(runar.Hash160(pubKey) == c.EcdsaPubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))

	// Step 2: Verify WOTS+
	runar.Assert(runar.Hash160(wotsPubKey) == c.WotsPubKeyHash)
	runar.Assert(runar.VerifyWOTS(sig, wotsSig, wotsPubKey))
}
