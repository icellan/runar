package runar

import (
	"math/big"
	"testing"
)

// N-102: the binary `/` and `%` operators lower to OP_DIV / OP_MOD, which
// truncate toward zero and ABORT the script on a zero divisor. The interpreter
// used to return 0 for a zero divisor, deriving a post-state the deployed
// script can never produce; the *big.Int helpers BigintBigDiv / BigintBigMod
// (what a .runar.go contract's `/` and `%` map to) did the same.
//
// Proves: anfEvalBinOp and the BigintBig helpers refuse a zero divisor
// (*ScriptOpcodeError / panic) and truncate toward zero (-7/2 = -3,
// -7%2 = -1). Does not prove: agreement with an executed script (the expected
// values are the OP_DIV/OP_MOD semantics, not an execution), nor anything
// about Go's native `/` on int64 operands.

func TestN102_AnfBinOpDivModZeroDivisorRefuses(t *testing.T) {
	for _, op := range []string{"/", "%"} {
		t.Run(op, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("script aborts on a zero divisor; interpreter returned a value")
				}
				if _, ok := r.(*ScriptOpcodeError); !ok {
					t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", r, r)
				}
			}()
			anfEvalBinOp(op, big.NewInt(7), big.NewInt(0), "")
		})
	}
}

func TestN102_AnfBinOpDivModTruncatesTowardZero(t *testing.T) {
	cases := []struct {
		op      string
		a, b, w int64
	}{
		{"/", -7, 2, -3}, {"%", -7, 2, -1}, {"/", 7, -2, -3}, {"%", 7, -2, 1},
	}
	for _, c := range cases {
		got, ok := anfEvalBinOp(c.op, big.NewInt(c.a), big.NewInt(c.b), "").(*big.Int)
		if !ok || got.Cmp(big.NewInt(c.w)) != 0 {
			t.Errorf("%d %s %d = %v, want %d", c.a, c.op, c.b, got, c.w)
		}
	}
}

func TestN102_BigintBigDivModZeroDivisorPanics(t *testing.T) {
	fns := map[string]func(a, b *big.Int) *big.Int{"BigintBigDiv": BigintBigDiv, "BigintBigMod": BigintBigMod}
	for name, fn := range fns {
		for _, zero := range []*big.Int{big.NewInt(0), nil} {
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("%s(17, %v): script aborts on a zero divisor; helper returned a value", name, zero)
					}
				}()
				fn(big.NewInt(17), zero)
			}()
		}
	}
}
