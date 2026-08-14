package contract

import runar "github.com/icellan/runar/packages/runar-go"

// R1K1Wallet provides a hardware-backed P-256 primary spend path and an
// independent secp256k1 recovery path. The P-256 commitment is salted per
// output; the private salt is supplied only in the R1 unlocking witness.
type R1K1Wallet struct {
	runar.SmartContract
	R1SaltedPubKeyHash runar.Addr `runar:"readonly"`
	K1PubKeyHash       runar.Addr `runar:"readonly"`
}

// SpendR1 verifies a YubiKey-compatible P-256 signature over the transaction
// digest after binding the supplied BIP-143 preimage to the current spend.
func (c *R1K1Wallet) SpendR1(r1Sig runar.ByteString, r1PubKey runar.ByteString, r1Salt runar.ByteString, txPreimage runar.SigHashPreimage) {
	runar.Assert(runar.Len(r1Salt) == 32)
	runar.Assert(runar.Hash160(runar.Cat(r1PubKey, r1Salt)) == c.R1SaltedPubKeyHash)
	runar.Assert(runar.Substr(txPreimage, runar.Len(txPreimage)-4, 4) == "41000000")
	runar.Assert(runar.CheckPreimage(txPreimage))
	runar.Assert(runar.VerifyECDSAP256(runar.Sha256Hash(txPreimage), r1Sig, r1PubKey))
}

// RecoverK1 spends through the independent mnemonic-derived recovery key.
func (c *R1K1Wallet) RecoverK1(k1Sig runar.Sig, k1PubKey runar.PubKey) {
	runar.Assert(runar.Hash160(k1PubKey) == c.K1PubKeyHash)
	runar.Assert(runar.CheckSig(k1Sig, k1PubKey))
}
