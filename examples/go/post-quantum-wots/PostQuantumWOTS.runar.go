//go:build ignore

package contract

import "runar"

type PostQuantumWOTS struct {
	runar.SmartContract
	Pubkey runar.ByteString `runar:"readonly"`
}

func (c *PostQuantumWOTS) Spend(msg runar.ByteString, sig runar.ByteString) {
	runar.Assert(runar.VerifyWOTS(msg, sig, c.Pubkey))
}
