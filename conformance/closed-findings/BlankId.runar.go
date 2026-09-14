// GK-BUG-009 control — the blank identifier `_`.
//
// `_ = x` is the Go / Rust / Zig discard idiom, and the Go DSL frontend emits
// it as an assignment TARGET, so `_` reaches the typechecker's Identifier arm
// as a name to be typed. Before GK-BUG-009 that arm returned "<unknown>" for
// anything it did not recognise, so `_` was carried by the fall-through in the
// six native tiers — and TS, which already raised "Undefined variable" there,
// refused this contract outright. Measured at the parent commit:
//
//   go rust python zig ruby java   7652957c009c77
//   ts                             Undefined variable '_'
//
// So invariant 1 was already broken for this shape, in the direction nobody
// looks: the REFERENCE tier was the outlier, and the six agreed. Teaching the
// new fall-through to raise would have flipped it to 7-vs-0 refusal and taken
// `compilers/go/frontend/intent_intrinsics_test.go` and the Ruby tier's
// equivalent down with it. `_` is listed as a discard in all seven instead.
//
// MUST COMPILE, in every tier, to the same bytes.
package x

import runar "github.com/icellan/runar/packages/runar-go"

type BlankId struct {
	runar.SmartContract
	Target runar.Bigint `runar:"readonly"`
}

func (c *BlankId) Verify(seed runar.Bigint) {
	doubled := seed * 2
	_ = doubled
	runar.Assert(seed == c.Target)
}
