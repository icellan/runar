//go:build ignore

// EXCLUDED FROM THE GO BUILD — `Ripemd160` cannot be a Go type and a Go
// function at once.
//
//	runar.Ripemd160 (value of type func(...) ...) is not a type
//
// The contract needs BOTH spellings: `ExpectedRipemd runar.Ripemd160` in type
// position and `runar.Ripemd160(preimage)` in call position. That is legal in
// the `.runar.go` surface, where parser_gocontract.go maps the name in
// mapGoType AND in mapGoBuiltin, and impossible in Go, where one identifier is
// either a type or a function.
//
// packages/runar-go resolves the collision in favour of the FUNCTION, on
// purpose: as a type, `runar.Ripemd160(x)` would silently compile as a
// conversion returning x and drop the hash — the defect that made the baked
// digest the spending key in two tiers (see
// conformance/go_surface_hash_spelling_execution_test.go). Fail loud beats fail
// open, and this exclusion is the noise that choice makes.
//
// The SHA-256 half of the same collision is already solvable: mapGoType carries
// `Sha256Digest` as an alias, so the field could be spelled that way. There is
// no peer entry for the RIPEMD-160 digest type — `runar.Ripemd160Hash` is
// rejected by the frontend with "unsupported type 'Ripemd160Hash' in property
// declaration". One entry mapping `Ripemd160Hash` to `Ripemd160` in the
// .runar.go type table of all seven compilers is what unblocks this file and
// state-ripemd160; that is a cross-tier parser change, not an examples change.
//
// `Split`, `Int2str` and `Ripemd160` in CALL position all resolve against
// packages/runar-go as of the commit that added them — the type annotations are
// the only remaining blocker.

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ByteBuiltins -- Go port. Executed coverage for five byte-level builtins that
// no conformance fixture called: Split, Int2Str, ReverseBytes, SHA-256 and
// RIPEMD-160. See the `.runar.ts` port for the full rationale.
//
// This port carries one thing none of the other eight can: the SHA-256 call is
// spelled `Sha256Hash`, not `Sha256`. `Sha256Hash` is a public export of
// `packages/runar-lang/src/builtins.ts` whose docstring claims every parser
// resolves it, but the Go surface parser is the ONLY one of the nine that maps
// it -- the TypeScript frontend rejects it outright with "Unknown function
// 'Sha256Hash'". Keeping the alias here is what gives the spelling its
// cross-tier gate: all seven compilers must agree it lowers to OP_SHA256,
// identically to the `sha256` the other eight surfaces call.
//
// `CheckSha256` keeps the `Sha256Hash` spelling on purpose and `CheckRipemd`
// below uses `runar.Ripemd160`, so this one fixture covers BOTH sides of the
// Go surface's name collision. `Sha256` and `Ripemd160` are each a Rúnar type
// name AND a Rúnar builtin name; in call position the builtin wins (see
// docs/formats/go.md). Two of the seven tiers used to resolve the collision as
// a type cast instead, which dropped the hash opcode entirely and made the
// baked digest the spending key -- see
// conformance/go_surface_hash_spelling_execution_test.go.
//
// `Split`, `Int2str` and `Ripemd160` all have counterparts in
// `packages/runar-go` now; the remaining blocker is the `runar.Sha256` /
// `runar.Ripemd160` TYPE annotations above, for the reason at the top of this
// file. `examples/go/loop-shapes`, named here as a peer exclusion, is built by
// Go now — its tag was a dead `import "runar"` path.
type ByteBuiltins struct {
	runar.SmartContract
	// ExpectedDigest is the SHA-256 digest baked into the locking script.
	ExpectedDigest runar.Sha256 `runar:"readonly"`
	// ExpectedRipemd is the RIPEMD-160 digest baked into the locking script.
	ExpectedRipemd runar.Ripemd160 `runar:"readonly"`
}

// CheckSplit exercises OP_SPLIT. Binds the right half of data at idx.
func (c *ByteBuiltins) CheckSplit(data runar.ByteString, idx runar.Int, expectedTail runar.ByteString) {
	tail := runar.Split(data, idx)
	runar.Assert(tail == expectedTail)
}

// CheckInt2Str exercises OP_NUM2BIN: fixed-width little-endian sign-magnitude.
func (c *ByteBuiltins) CheckInt2Str(value runar.Int, width runar.Int, expected runar.ByteString) {
	// `Int2Str`, `Int2str` and `int2str` all resolve, in all seven tiers.
	// `Int2Str` — the spelling docs/formats/go.md documents — used to be in
	// three builtin tables only; go/rust/python/java camel-cased the leading
	// character to `int2Str` and rejected the call. Fixed, and gated by
	// conformance/subtype-parity/GoBuiltinAliasSpelling.runar.go.
	s := runar.Int2str(value, width)
	runar.Assert(s == expected)
}

// CheckReverse exercises the 520 unrolled OP_SPLIT / OP_CAT iterations.
func (c *ByteBuiltins) CheckReverse(data runar.ByteString, expected runar.ByteString) {
	r := runar.ReverseBytes(data)
	runar.Assert(r == expected)
}

// CheckSha256 exercises OP_SHA256 through the `Sha256Hash` alias spelling.
func (c *ByteBuiltins) CheckSha256(preimage runar.ByteString) {
	h := runar.Sha256Hash(preimage)
	runar.Assert(h == c.ExpectedDigest)
}

// CheckRipemd exercises OP_RIPEMD160 through `runar.Ripemd160`, the Go
// surface's only spelling for the hash and the ambiguous half of the collision
// described above.
func (c *ByteBuiltins) CheckRipemd(preimage runar.ByteString) {
	h := runar.Ripemd160(preimage)
	runar.Assert(h == c.ExpectedRipemd)
}
