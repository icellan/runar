//go:build ignore

// EXCLUDED FROM THE GO BUILD — the fixture's whole point is two Go types the
// DSL unifies and Go does not.
//
//	invalid operation: a + b (mismatched types runar.Bigint and runar.BigintBig)
//
// `Check(a runar.Bigint, b runar.BigintBig)` adds the two together because the
// .runar.go parser maps BOTH to the single Rúnar primitive `bigint`. In Go they
// are `int64` and `*big.Int`, and there is no arithmetic between them. Making
// them add would mean giving up the very distinction the fixture exists to
// exercise.
//
// Same root cause as integer-boundary, schnorr-zkp, p256-primitives and
// p384-primitives: Rúnar's `bigint` is arbitrary precision and the Go mock's
// `Bigint` is int64.

package contract

import "runar"

// Exercises two Go-DSL features at once:
//   1. `runar.BigintBig` declared as a property type — the DSL parser maps
//      this to the same `bigint` primitive as `runar.Bigint`, so arithmetic
//      / comparison works against ordinary Bigint values.
//   2. `runar.ByteString("literal")` as an inline byte-string literal — the
//      DSL parser decodes the Go string escape sequences (\x00, \x6a) and
//      emits a ByteString literal whose hex value represents the raw bytes.
type GoDslBytestringLiteral struct {
	runar.SmartContract
	Target   runar.BigintBig  `runar:"readonly"`
	Expected runar.ByteString `runar:"readonly"`
}

func (c *GoDslBytestringLiteral) Check(a runar.Bigint, b runar.BigintBig) {
	runar.Assert(a+b == c.Target)
	runar.Assert(runar.ByteString("\x00\x6a") == c.Expected)
}
