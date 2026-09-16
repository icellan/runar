//go:build ignore

// MultiSig2of3 — a 2-of-3 multi-signature contract.
//
// Funds are locked to three public keys. To spend, the unlocker must supply
// two valid ECDSA signatures from any two of the committed keys. The signing
// pair can be (pk1,pk2), (pk1,pk3), or (pk2,pk3); the order of the supplied
// signatures must match the order of the corresponding pubkeys in the
// committed array.
//
// EXCLUDED FROM THE GO BUILD — the array spelling three tiers require does not
// convert to the slice the mock takes.
//
//	cannot use [2]runar.Sig{…} (value of type [2]runar.Sig) as []runar.Sig
//	value in argument to runar.CheckMultiSig
//
// runar.CheckMultiSig([2]runar.Sig{sig1, sig2}, [3]runar.PubKey{...}) lowers to
// two array_literal ANF nodes, one per array argument. packages/runar-go
// declares CheckMultiSig([]Sig, []PubKey), and a Go array does not convert to a
// slice implicitly, so the contract does not build as Go.
//
// The slice spelling `[]runar.Sig{...}` was tried and REVERTED. It compiles as
// Go and the Go tier emits byte-identical ANF for both forms -- but three of the
// seven .runar.go parsers reject it: TypeScript and Ruby flatten the elements
// and report "checkMultiSig() expects 2 arguments, got 6", and Zig fails to
// parse `[]runar.Sig{` outright. Proving IR identity with the Go binary alone
// and generalising to seven tiers is agreement mistaken for evidence; the
// all-tier `--multi-format` run is what caught it (735/736, multisig
// [.runar.go]).
//
// Two ways out, neither an examples-level change: teach the TS, Zig and Ruby
// .runar.go parsers the slice composite literal, or relax the mock's
// CheckMultiSig to accept arrays as well as slices — which costs the static
// element type on a crypto entry point, so it is a deliberate API decision
// rather than a tidy-up.
//
// The array_literal node this fixture is the canonical callsite for is still
// covered cross-tier: the other eight surfaces compile and the .runar.go
// surface is exercised by every tier's parser in the --parser-only matrix.
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
