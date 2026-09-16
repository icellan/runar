//go:build ignore

// EXCLUDED FROM THE GO BUILD — every literal in this fixture overflows int64 by
// design.
//
//	cannot use 4294967295 * 4294967295 (untyped int constant
//	18446744065119617025) as int value in assignment (overflows)
//
// The contract pins the seven tiers to ONE arbitrary-precision integer domain
// (issue #162): each operand fits a signed 64-bit slot and each folded result
// escapes one. Go evaluates untyped constants exactly and then requires them to
// fit the type they land in, so `go build` rejects all four assignments.
//
// Widening the runtime type does not reach this. `runar.BigintBig` is
// *big.Int, and no Go constant expression converts to a pointer:
// `runar.BigintBig(18446744065119617025)` is not a conversion Go accepts, and
// `big.NewInt` overflows on the argument before it is called. Reaching the
// value at all would need a constructor taking a string — new surface syntax
// in all seven .runar.go parsers — and that would defeat the fixture, whose
// claim is that a BARE literal folds to the same bytes in nine formats.
//
// A Go port that fit in int64 would not be this fixture. Shares a root cause
// with go-dsl-bytestring-literal and schnorr-zkp — a bigint literal wider than
// int64 has no Go spelling — and NOT with p256-primitives / p384-primitives,
// which were grouped here, pass their scalar straight to a *big.Int parameter,
// and build now that the parameter is typed `runar.BigintBig`.

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
