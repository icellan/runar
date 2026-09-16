package conformance

import (
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// Rúnar's `/` on NEGATIVE operands, spent on the consensus interpreter.
//
// WHY THIS FILE EXISTS. `examples/go/arithmetic` is one of 32 ports in
// examples/go that carried `//go:build ignore` and so was never compiled as
// Go: its native business logic ran nowhere, and the only thing exercised was
// the Rúnar frontend. Un-excluding it made `a / b` runnable natively, which
// immediately raises the question a compile-only suite could not ask -- does
// Go's int64 `/` give the same answer as the emitted OP_DIV?
//
// The two truncate the same way, but only on paper. -7/2 is -3 under
// truncation toward zero and -4 under floor division; Python's `//` floors,
// and the Python tier's parser feeds the same fixture. A tier that floored
// would agree with every positive operand and disagree with every negative
// one, which is exactly the shape that survives a suite of positive examples.
//
// So each row below computes the whole expression in Go and then spends the
// COMPILED locking script with that value baked in as `target`. The compiler
// under test is TypeScript, the arithmetic is Go's, and the judge is the
// go-sdk consensus engine.
//
// The native half of the same table is
// examples/go/arithmetic/Arithmetic_test.go.
// ---------------------------------------------------------------------------

// spendArithmetic bakes `target` into the arithmetic fixture's locking script
// and spends Verify(a, b). One public method, so there is no method selector
// to push. Reports whether the consensus interpreter ACCEPTED.
func spendArithmetic(t *testing.T, target, a, b int64) bool {
	t.Helper()
	lockingHex, err := compileRúnar("arithmetic", fmt.Sprintf(`{"target":"%d"}`, target))
	if err != nil {
		t.Fatalf("compile (target=%d): %v", target, err)
	}
	return executeScript(lockingHex, encodePushInt(a)+encodePushInt(b)) == nil
}

func TestArithmetic_DivisionTruncatesTowardZero_OnChain(t *testing.T) {
	// Verify asserts (a+b) + (a-b) + (a*b) + (a/b) == target.
	expr := func(a, b int64) int64 { return (a + b) + (a - b) + (a * b) + (a / b) }

	// floorExpr is the same expression with FLOOR division, which is what a
	// Python-style `//` lowering would produce. For every negative row below
	// it differs from expr, and the test requires the script to refuse it.
	floorDiv := func(a, b int64) int64 {
		q := a / b
		if (a%b != 0) && ((a < 0) != (b < 0)) {
			q--
		}
		return q
	}
	floorExpr := func(a, b int64) int64 { return (a + b) + (a - b) + (a * b) + floorDiv(a, b) }

	for _, c := range []struct{ a, b int64 }{
		// Positive rows first: they must keep passing, or a "fix" that broke
		// division outright would look like a pass on the negative rows.
		{10, 3}, {7, 2}, {1, 1}, {100, 7},
		// The rows that separate truncation from floor.
		{-7, 2}, {7, -2}, {-7, -2}, {-1, 2}, {1, -2}, {-100, 7},
	} {
		a, b := c.a, c.b
		t.Run(fmt.Sprintf("a=%d,b=%d", a, b), func(t *testing.T) {
			want := expr(a, b)

			if !spendArithmetic(t, want, a, b) {
				t.Fatalf("(%d+%d)+(%d-%d)+(%d*%d)+(%d/%d) == %d was REFUSED: "+
					"the emitted OP_DIV disagrees with Go's truncating int64 "+
					"division", a, b, a, b, a, b, a, b, want)
			}

			// Teeth: a neighbouring target must be refused, or the row above
			// passes on a script that ignores its operands.
			if spendArithmetic(t, want+1, a, b) {
				t.Fatalf("target %d (one past the real result) was also "+
					"ACCEPTED", want+1)
			}

			if floor := floorExpr(a, b); floor != want {
				if spendArithmetic(t, floor, a, b) {
					t.Fatalf("the FLOOR-division result %d was accepted where "+
						"truncation gives %d: `/` is flooring on negative "+
						"operands", floor, want)
				}
			}
		})
	}
}
