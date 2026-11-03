//go:build ignore

// MultiSigVerifyFused -- see MultiSigVerifyFused.runar.ts. Excluded from the Go
// build for the same reason as the `multisig` fixture: the array spelling the
// other tiers require does not convert to the slice the mock takes.
package contract

import "runar"

type MultiSigVerifyFused struct {
	runar.SmartContract
	Pk1 runar.PubKey `runar:"readonly"`
	Pk2 runar.PubKey `runar:"readonly"`
	Pk3 runar.PubKey `runar:"readonly"`
}

func (c *MultiSigVerifyFused) Unlock(sig1 runar.Sig, sig2 runar.Sig, amount runar.Bigint) {
	runar.Assert(runar.CheckMultiSig(
		[2]runar.Sig{sig1, sig2},
		[3]runar.PubKey{c.Pk1, c.Pk2, c.Pk3}))
	runar.Assert(amount > 0)
}
