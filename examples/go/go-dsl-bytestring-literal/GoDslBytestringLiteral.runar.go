//go:build ignore

// EXCLUDED FROM THE GO BUILD — the fixture's whole point is two Go types the
// DSL unifies and Go does not.
//
//	invalid operation: a + b (mismatched types runar.Bigint and runar.BigintBig)
//
// `Check(a runar.Bigint, b runar.BigintBig)` adds the two together because the
// .runar.go parser maps BOTH to the single Rúnar primitive `bigint`. In Go they
// are `int64` and `*big.Int`, and there is no arithmetic between them.
//
// Every escape from this deletes the fixture. Typing both parameters the same
// way removes the distinction it exists to prove. Spelling the addition
// `runar.BigintBigAdd(a, b)` — the helper the parser rewrites back into `+`,
// and the one ec-primitives and ec-demo use — needs both operands to be
// *big.Int, which is the same surrender with more syntax. Go has no operator
// overloading, so there is no third option: this is the one place in
// examples/go where "valid Go AND valid Rúnar" is genuinely unsatisfiable
// rather than merely unimplemented.
//
// NOT the same root cause as p256-primitives / p384-primitives, which used to
// be grouped with it here. Those only PASSED a scalar to a *big.Int parameter,
// so typing it `runar.BigintBig` fixed them and they build now. The three that
// remain — this one, integer-boundary and schnorr-zkp — are about arithmetic
// and literals, not about a parameter type.

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
