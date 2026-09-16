//go:build ignore

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ByteBuiltins -- Go port. Executed coverage for four byte-level builtins that
// no conformance fixture called: Split, Int2Str, ReverseBytes and SHA-256.
// See the `.runar.ts` port for the full rationale.
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
// Do NOT "simplify" this to `runar.Sha256(preimage)`. That spelling collides
// with the `Sha256` TYPE name, and the TypeScript and Ruby compilers lower the
// collision to an identity binding -- the hash opcode is never emitted, while
// the other five tiers emit OP_SHA256. `runar.Ripemd160` has the same defect,
// which is why ripemd160 is absent from this fixture entirely.
//
// `//go:build ignore` because `Split` and `Int2Str` have no counterpart in
// `packages/runar-go`; this file is a Rúnar frontend input, not a Go one. The
// same tag is on `examples/go/loop-shapes` and 26 other ports.
type ByteBuiltins struct {
	runar.SmartContract
	// ExpectedDigest is the SHA-256 digest baked into the locking script.
	ExpectedDigest runar.Sha256 `runar:"readonly"`
}

// CheckSplit exercises OP_SPLIT. Binds the right half of data at idx.
func (c *ByteBuiltins) CheckSplit(data runar.ByteString, idx runar.Int, expectedTail runar.ByteString) {
	tail := runar.Split(data, idx)
	runar.Assert(tail == expectedTail)
}

// CheckInt2Str exercises OP_NUM2BIN: fixed-width little-endian sign-magnitude.
func (c *ByteBuiltins) CheckInt2Str(value runar.Int, width runar.Int, expected runar.ByteString) {
	// Int2str, not Int2Str. `Int2Str` is the spelling in the TypeScript
	// parser's GO_BUILTIN_MAP, and go/rust/python/java all REJECT it: those four
	// camel-case the leading character (Int2Str -> int2Str) instead of consulting
	// the alias map, and the builtin is registered as `int2str`. `Int2str` and
	// `int2str` both resolve in all seven tiers.
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
