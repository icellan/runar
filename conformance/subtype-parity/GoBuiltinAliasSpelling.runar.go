//go:build ignore

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// F5 — `runar.Int2Str` is the spelling `docs/formats/go.md` and the TypeScript
// parser's Go builtin table both document, and four tiers rejected it with
// "unknown function 'int2Str'".
//
// The Go surface resolves a builtin in two steps: consult the alias table, and
// otherwise lower-case the leading character. Every alias whose Rúnar name is
// NOT just its Go name with a lower-cased first letter therefore has to be in
// the table of all seven tiers or it falls through to the default rule and
// produces a name that exists nowhere. There are seven such aliases —
// `Sha256Hash`, `Num2Bin`, `Bin2Num`, `Int2Str`, `ToBool`, `VerifyECDSAP256`,
// `VerifyECDSAP384`. Six were in all seven tables; `Int2Str` was in two (zig,
// ruby) plus the TypeScript reference, and go / rust / python / java
// camel-cased it to `int2Str` instead. The builtin is registered `int2str`.
//
// It failed loudly, which is why this is a small defect and not the one in
// GoHashSpelling.runar.go. It still split the seven tiers on a documented
// spelling, and nothing gated the alias table: the aliases were only ever
// exercised by whichever spelling a fixture author happened to pick.
//
// All three spellings must keep working, in every tier:
//   - `Int2Str`  — the documented alias, table lookup
//   - `Int2str`  — the default rule, lower-case the leading character
//   - `int2str`  — the Rúnar name, already lower-case
//
// Only the first two appear here. `runar.int2str` is not a legal reference in
// Go — the identifier is unexported — and this file stays readable Go even
// though the frontend is its only consumer. The all-lower-case spelling is
// pinned instead by the per-tier parser unit tests, which have no such
// constraint.
//
// The peer aliases ride along so the table itself is gated, not just the one
// entry that was missing. `Sha256Hash`, `ToBool`, `Num2Bin` and `Bin2Num` fall
// through to a nonexistent name (`sha256Hash`, `toBool`, `num2Bin`, `bin2Num`)
// the moment a tier drops them, exactly as `Int2Str` did. That is five of the
// seven at-risk aliases. The other two, `VerifyECDSAP256` and `VerifyECDSAP384`,
// are not reachable from a fixture this small — they need P-256/P-384 point
// operands — and are present in all seven tables today; the TypeScript-side
// unit test in `01-parse-go.test.ts` enumerates the full class so a new alias
// cannot be added to the reference tier without being noticed.
//
// `//go:build ignore`: a Rúnar frontend input, not a Go compilation unit.
type GoBuiltinAliasSpelling struct {
	runar.SmartContract
	Expected runar.ByteString `runar:"readonly"`
}

// Unlock runs each spelling on arguments the constant folder cannot see
// through, so no tier can agree by folding the call away.
func (c *GoBuiltinAliasSpelling) Unlock(value runar.Int, width runar.Int, flag runar.Int) {
	documented := runar.Int2Str(value, width)
	defaulted := runar.Int2str(value, width)
	runar.Assert(documented == defaulted)

	// The peer aliases, whose Rúnar names are likewise not the lower-cased-
	// leading-character form of their Go names.
	packed := runar.Num2Bin(value, width)
	unpacked := runar.Bin2Num(packed)
	runar.Assert(unpacked == value)
	runar.Assert(runar.ToBool(flag))

	runar.Assert(runar.Sha256Hash(documented) == c.Expected)
}
