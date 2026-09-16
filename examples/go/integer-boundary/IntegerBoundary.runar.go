//go:build ignore

// EXCLUDED FROM THE GO BUILD — every literal in this fixture overflows int64 by
// design.
//
//	cannot use 4294967295 * 4294967295 (untyped int constant
//	18446744065119617025) as int value in assignment (overflows)
//
// The contract pins the seven tiers to ONE arbitrary-precision integer domain
// (issue #162): each operand fits a signed 64-bit slot and each folded result
// escapes one. `runar.Int` aliases int64 in the Go mock, so `go build` rejects
// all four assignments at compile time — the constants are untyped and Go
// evaluates them exactly.
//
// A Go port that fit in int64 would not be this fixture. Same root cause as
// go-dsl-bytestring-literal, schnorr-zkp and the two NIST primitive ports.

package contract

import "runar"

// IntegerBoundary pins the seven tiers to one arbitrary-precision integer
// domain (issue #162). Every literal fits a signed 64-bit slot; every folded
// result escapes one. See the TypeScript source for the full note.
type IntegerBoundary struct {
	runar.SmartContract
	Target runar.Int `runar:"readonly"`
}

func (c *IntegerBoundary) Verify(delta runar.Int) {
	p := 4294967295 * 4294967295
	q := 9223372036854775807 + 1
	r := 4294967296 * 4294967296
	s := 9223372036854775807 * 9223372036854775807
	runar.Assert(p+q+r+s+delta == c.Target)
}
