//go:build ignore

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// F1 — `Sha256` and `Ripemd160` are BOTH Rúnar type names and Rúnar builtin
// names, and the `.runar.go` surface spells both with the same
// `runar.Name(arg)` syntax. In CALL position the builtin wins.
//
// That is decided, not discovered: `docs/formats/go.md` has documented
// `runar.Sha256(data)` -> `sha256(data)` and `runar.Ripemd160(data)` ->
// `ripemd160(data)` since the surface shipped, and five of the seven tiers
// implemented it. The TypeScript and Ruby parsers listed both names in their
// type-cast table and tried the cast branch FIRST, so the call unwrapped to an
// identity binding and the hash opcode vanished — `assert(sha256(x) == digest)`
// became `assert(x == digest)`, with the digest sitting in the locking script
// for anyone to read and push. `conformance/go_surface_hash_spelling_execution_test.go`
// spends exactly that script on the consensus interpreter.
//
// The cast reading loses nothing: `Sha256` and `Ripemd160` are ByteString
// subtypes, so `runar.Sha256(x)` as a conversion was an identity on the value
// and a no-op on the bytes. The function reading is the only one of the two
// that can emit an opcode, and it is the one the docs promise.
//
// This fixture is the cross-tier half of the gate: every tier must accept it
// AND compile it to byte-identical hex, so a tier that resolves one of these
// names to a cast diverges here in bytes, loudly, on the first run.
//
// The unambiguous peers ride along deliberately. Without them a "fix" that
// disabled hashing outright in the Go surface would still produce seven
// identical scripts.
//
// `//go:build ignore`: this is a Rúnar frontend input under conformance/, not
// a Go compilation unit. (It used to cite "examples/go/byte-builtins and 26
// other ports" as peers. 24 of those 27 were excluded only by a dead
// `import "runar"` path and are built by Go now; byte-builtins is one of the
// eight that remain, each with its reason written into the file.)
type GoHashSpelling struct {
	runar.SmartContract
	Expected runar.ByteString `runar:"readonly"`
}

// Unlock chains the four spellings so each one's result feeds the next. A tier
// that drops any single hash produces a different script for the whole method,
// which is what makes the byte-identity assertion sharp.
func (c *GoHashSpelling) Unlock(preimage runar.ByteString) {
	// The two ambiguous names — the defect itself.
	a := runar.Sha256(preimage)
	b := runar.Ripemd160(a)
	// The two names that are NOT also type names, as the control.
	d := runar.Sha256Hash(b)
	e := runar.Hash160(d)
	runar.Assert(e == c.Expected)
}
