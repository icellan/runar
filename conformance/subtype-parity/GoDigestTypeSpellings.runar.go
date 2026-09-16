//go:build ignore

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// F1-type — the TYPE half of the `Sha256` / `Ripemd160` name collision.
//
// GoHashSpelling.runar.go in this directory gates the CALL half: in call
// position `runar.Sha256(x)` must be the hash builtin and not an identity cast.
// This file gates the other half of the same collision, which was left
// unfinished.
//
// Go cannot bind one identifier to both a type and a function, so
// packages/runar-go binds the FUNCTION — `runar.Sha256` and `runar.Ripemd160`
// are `func`s — and spells the DIGEST TYPES `runar.Sha256Digest` and
// `runar.Ripemd160Hash`. Those are the only two names a `.runar.go` contract
// can put in type position and still be valid Go, which is the point of the
// surface: a `.runar.go` file compiles as Go, against the mock types under
// `go test`, AND as Rúnar.
//
// Only half of that was implemented. All seven `.runar.go` type tables carried
// `Sha256Digest`; not one carried `Ripemd160Hash`. They carried the bare name
// `Ripemd160`, which packages/runar-go does not declare as a type at all — so
// the surface accepted a spelling that does not exist and refused the one that
// does, with `unsupported type 'Ripemd160Hash' in property declaration`.
// docs/formats/go.md documented the non-existent spelling, and
// examples/go/state-ripemd160 and examples/go/byte-builtins were both held out
// of the Go build by it.
//
// SEVEN TIERS AGREEING IS NOT THE CLAIM. All seven agreed before this fixture
// existed — they agreed on refusing the real type name. The claim is that
// `Ripemd160Hash` resolves to the SAME Rúnar primitive as the canonical
// `Ripemd160`, and that is GoDigestTypeSpellingsRef.runar.ts: the identical
// program written with the primitive names. subtype-parity.test.ts compiles
// both in every tier and requires one hex.
//
// WHY THE CONTRACT IS STATEFUL. This was written stateless first, and the pair
// was vacuous: with the digests as readonly properties, re-pointing
// `Ripemd160Hash` at `ByteString` in a tier's type table produced BYTE-IDENTICAL
// script. Every domain type is a ByteString subtype, the families are
// bidirectionally assignable, and no tier emits a length check for a
// domain-typed argument (spec/type-system.md §6.1) — so in that shape a wrong
// mapping is invisible and the guard could not fail.
//
// Stateful state deserialization is where the type is load-bearing: each
// mutable property is read back at a width its TYPE decides
// (spec/type-system.md §6, "Ripemd160 | 20 bytes pushed directly"). Measured on
// this contract in the Go tier: `Ripemd160Hash` emits 1359 hex chars,
// `Sha256Digest` 1359 DIFFERENT ones, `ByteString` 1615. So the two wrong
// mappings a copy-paste would produce — the sibling digest, or the base type —
// both diverge from the reference peer, and the removal case fails acceptance.
//
// Both digest types appear as state AND as method parameters. The parameter
// rows gate acceptance only, for the reason above; the state rows are what put
// the mapping in the bytes.
//
// `//go:build ignore`: this is a Rúnar frontend input under conformance/, not a
// Go compilation unit. Unlike most fixtures here it would compile as Go — every
// name in it is declared by packages/runar-go, which is what it is asserting.
type GoDigestTypeSpellings struct {
	runar.StatefulSmartContract
	// Mutable state. The width each is deserialized at is decided by its type,
	// which is what makes a wrong mapping change the script bytes.
	Sha    runar.Sha256Digest
	Ripemd runar.Ripemd160Hash
}

// Update rewrites both digests from one preimage, so the two hash builtins are
// exercised in call position in the same file that exercises their digest types
// in type position.
func (c *GoDigestTypeSpellings) Update(preimage runar.ByteString) {
	c.Sha = runar.Sha256(preimage)
	c.Ripemd = runar.Ripemd160(preimage)
}

// Check takes both digest types as PARAMETERS. Parameter types cost no script
// bytes, so this method gates acceptance rather than bytes: a tier that mapped
// the spelling in property position only would refuse here.
func (c *GoDigestTypeSpellings) Check(witnessSha runar.Sha256Digest, witnessRipemd runar.Ripemd160Hash) {
	runar.Assert(witnessSha == c.Sha)
	runar.Assert(witnessRipemd == c.Ripemd)
}
