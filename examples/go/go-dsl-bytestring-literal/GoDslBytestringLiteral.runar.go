//go:build ignore

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
