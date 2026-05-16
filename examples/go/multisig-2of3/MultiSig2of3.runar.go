//go:build ignore

// MultiSig2of3 — a 2-of-3 multi-signature contract.
//
// Funds are locked to three public keys. To spend, the unlocker must supply
// two valid ECDSA signatures from any two of the committed keys. The signing
// pair can be (pk1,pk2), (pk1,pk3), or (pk2,pk3); the order of the supplied
// signatures must match the order of the corresponding pubkeys in the
// committed array.
//
// runar.CheckMultiSig([2]runar.Sig{sig1, sig2}, [3]runar.PubKey{...}) lowers
// to two array_literal ANF nodes — one per array argument. The Go reference
// parser is built on go/parser so it requires native Go composite-literal
// syntax (`[N]T{...}`); every other tier's .runar.go parser unwraps the
// typed-array form (or accepts a bare `[a, b, …]` body) so the contract
// lowers to identical Stack IR across all seven compilers.
//
// Script layout:
//
//	Unlocking: <sig1> <sig2>
//	Locking:   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
//	           OP_VERIFY
package contract

import "runar"

type MultiSig2of3 struct {
	runar.SmartContract
	Pk1 runar.PubKey `runar:"readonly"`
	Pk2 runar.PubKey `runar:"readonly"`
	Pk3 runar.PubKey `runar:"readonly"`
}

// Unlock requires two valid signatures from any two of the three committed pubkeys.
func (c *MultiSig2of3) Unlock(sig1 runar.Sig, sig2 runar.Sig) {
	runar.Assert(runar.CheckMultiSig(
		[2]runar.Sig{sig1, sig2},
		[3]runar.PubKey{c.Pk1, c.Pk2, c.Pk3}))
}
