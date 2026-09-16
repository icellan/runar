package contract

import runar "github.com/icellan/runar/packages/runar-go"

// HashRegistry -- a stateful contract whose single mutable field is a
// RIPEMD-160 digest.
//
// This port carried `//go:build ignore` for as long as it existed. The reason
// written at the top of it was accurate: `CurrentHash runar.Ripemd160` needs
// `Ripemd160` in TYPE position, and packages/runar-go binds that identifier to
// the hash FUNCTION, because Go cannot bind one identifier to both and the type
// reading is the one that fails open -- as a type, `runar.Ripemd160(x)` is a
// conversion that returns x and drops the hash.
//
// The fix was the one that reason named: `packages/runar-go` already declared
// the digest TYPE as `Ripemd160Hash`, and no tier's `.runar.go` type table
// mapped that spelling -- while all seven mapped `Sha256Digest`, its SHA-256
// peer, for exactly the same reason. Adding the missing arm to the seven
// tables is what un-excluded this file and examples/go/byte-builtins.
//
// `conformance/subtype-parity/GoDigestTypeSpellings.runar.go` is the guard that
// keeps the two spellings from drifting apart again.
type HashRegistry struct {
	runar.StatefulSmartContract
	CurrentHash runar.Ripemd160Hash // no tag = mutable state
}

// Update replaces the registered digest.
func (c *HashRegistry) Update(newHash runar.Ripemd160Hash) {
	c.CurrentHash = newHash
	runar.Assert(true)
}
