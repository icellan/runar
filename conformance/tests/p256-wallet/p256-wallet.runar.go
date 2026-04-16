//go:build ignore

package contract

import "runar"

type P256Wallet struct {
	runar.SmartContract
	EcdsaPubKeyHash runar.Addr       `runar:"readonly"`
	P256PubKeyHash  runar.ByteString `runar:"readonly"`
}

func (c *P256Wallet) Spend(p256Sig runar.ByteString, p256PubKey runar.ByteString, sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.EcdsaPubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
	runar.Assert(runar.Hash160(p256PubKey) == c.P256PubKeyHash)
	runar.Assert(runar.VerifyECDSAP256(sig, p256Sig, p256PubKey))
}
