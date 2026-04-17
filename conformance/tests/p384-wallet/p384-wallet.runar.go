//go:build ignore

package contract

import "runar"

type P384Wallet struct {
	runar.SmartContract
	EcdsaPubKeyHash runar.Addr       `runar:"readonly"`
	P384PubKeyHash  runar.ByteString `runar:"readonly"`
}

func (c *P384Wallet) Spend(p384Sig runar.ByteString, p384PubKey runar.ByteString, sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.EcdsaPubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
	runar.Assert(runar.Hash160(p384PubKey) == c.P384PubKeyHash)
	runar.Assert(runar.VerifyECDSAP384(sig, p384Sig, p384PubKey))
}
