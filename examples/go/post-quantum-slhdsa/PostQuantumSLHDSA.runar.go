//go:build ignore

package contract

import "runar"

type PostQuantumSLHDSA struct {
	runar.SmartContract
	Pubkey runar.ByteString `runar:"readonly"`
}

func (c *PostQuantumSLHDSA) Spend(msg runar.ByteString, sig runar.ByteString) {
	runar.Assert(runar.VerifySLHDSA_SHA2_128s(msg, sig, c.Pubkey))
}
