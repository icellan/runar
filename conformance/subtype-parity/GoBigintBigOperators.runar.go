//go:build ignore

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// R-Bigint — the eleven `runar.BigintBig*` operator helpers, all in one file.
//
// `runar.BigintBig` is `*big.Int` in packages/runar-go, and Go has no operator
// overloading: `a < b` does not compile on two of them, and `a == b` compiles
// into POINTER IDENTITY, which is worse than not compiling. So a `.runar.go`
// contract that carries arbitrary-precision values — a 256-bit curve
// coordinate, a NIST scalar — spells its arithmetic as a call, and the parser
// rewrites the call back into the operator. `runar.BigintBigEqual(a, b)` has to
// emit the bytes `a === b` emits, or the spelling is a trap rather than an
// affordance.
//
// WHY THIS FILE EXISTS. That rewrite lived in compilers/go and NOWHERE ELSE,
// on main, for as long as it had existed. All seven tiers parse `.runar.go`
// (CLAUDE.md invariant 1, "frontend parity, no exceptions"), and the other six
// rejected every one of these spellings as `unknown function 'bigintBigEqual'`.
// It went undetected because no fixture used them: the Go SDK shipped the type
// and the helpers, docs pointed at them, and six tiers refused the program.
//
// It surfaced when examples/go/ec-primitives started using `BigintBigEqual` for
// 256-bit coordinates and `--multi-format` failed 3 of 736. The instance is
// fixed by porting the table to the six tiers. This file fixes the CLASS: the
// corpus in this directory requires every tier to ACCEPT each fixture and to
// emit BYTE-IDENTICAL hex, so a tier that gains or loses one of these spellings
// fails here immediately rather than waiting for a fixture to happen to use it.
//
// The peer claim — that each helper emits what its OPERATOR emits, not merely
// what the other tiers' copies of the same helper emit — is
// GoBigintBigOperatorsRef.runar.ts, which is this contract written with `+`,
// `<`, `===`. `subtype-parity.test.ts` compiles both and requires one hex.
// Without that pair, seven tiers agreeing on a wrong rewrite would still pass.
//
// All eleven helpers appear below. An absent one is an untested one, which is
// the exact condition this file was written to end.
type GoBigintBigOperators struct {
	runar.SmartContract
	Expected runar.BigintBig `runar:"readonly"`
}

// CheckArithmetic exercises Add, Sub, Mul, Div, Mod and Equal.
func (c *GoBigintBigOperators) CheckArithmetic(a runar.BigintBig, b runar.BigintBig) {
	sum := runar.BigintBigAdd(a, b)
	diff := runar.BigintBigSub(a, b)
	prod := runar.BigintBigMul(a, b)
	quot := runar.BigintBigDiv(a, b)
	rem := runar.BigintBigMod(a, b)
	total := runar.BigintBigAdd(runar.BigintBigAdd(sum, diff), runar.BigintBigAdd(prod, runar.BigintBigAdd(quot, rem)))
	runar.Assert(runar.BigintBigEqual(total, c.Expected))
}

// CheckWideEncoders exercises the two *Big encoder spellings, which sat in
// exactly the same position as the operator helpers: compilers/go folded
// `Num2BinBig` / `Bin2NumBig` onto `num2bin` / `bin2num`, and the other six
// tiers fell through to the default leading-character rule and produced
// `num2BinBig` / `bin2NumBig`, names no builtin registry has. The suffix names
// a different Go RUNTIME type — *big.Int, so the Go-side mock does not
// truncate — not a different Script operation, so the bytes must be the ones
// the unsuffixed spelling produces. GoBigintBigOperatorsRef.runar.ts writes
// this method with `num2bin` / `bin2num` and the pair must agree.
func (c *GoBigintBigOperators) CheckWideEncoders(a runar.BigintBig) {
	encoded := runar.Num2BinBig(a, 8)
	runar.Assert(runar.BigintBigEqual(runar.Bin2NumBig(encoded), c.Expected))
}

// CheckComparisons exercises Less, LessEq, Greater, GreaterEq, Equal and
// NotEqual. Each is asserted in the direction that makes it true for a < b, so
// a tier that lowered any of the six to the wrong operator produces different
// bytes than the reference spelling in GoBigintBigOperatorsRef.runar.ts.
func (c *GoBigintBigOperators) CheckComparisons(a runar.BigintBig, b runar.BigintBig) {
	runar.Assert(runar.BigintBigLess(a, b))
	runar.Assert(runar.BigintBigLessEq(a, b))
	runar.Assert(runar.BigintBigGreater(b, a))
	runar.Assert(runar.BigintBigGreaterEq(b, a))
	runar.Assert(runar.BigintBigNotEqual(a, b))
	runar.Assert(runar.BigintBigEqual(a, a))
}
