package runar

import (
	"math/big"
	"strings"
	"testing"
)

// F-134: the Go mocks of the math builtins (what a .runar.go contract calls
// under `go test`) and the SDK ANF interpreter (what derives a call's
// post-state) must compute what the compiled script computes.
//
// The expected column was established by EXECUTING the TS compiler's script
// for each builtin in @bsv/sdk's Spend (fold ON and OFF, identical): OP_DIV /
// OP_MOD truncate toward zero; a zero divisor aborts; pow aborts outside
// 0 <= exp <= 32 (OP_WITHIN guard); sqrt aborts on n < 0 and n >= 2^495.
// "abort" means the script fails, so the runtime must refuse (panic /
// *ScriptOpcodeError) rather than return a number.
//
// Proves: for each listed input the native mock and the interpreter return
// the script's value or refuse where the script aborts. Does not prove:
// agreement outside the table, or anything about the script itself (it is
// the oracle here, not the subject). mock_script_agreement_test.go executes
// the in-domain rows against the Go-compiled script.

type f134Vector struct {
	fn    string
	args  []*big.Int
	want  *big.Int // nil = script aborts
	label string
}

func f134Vectors() []f134Vector {
	p495 := new(big.Int).Lsh(big.NewInt(1), 495)
	v := func(fn string, want *big.Int, args ...int64) f134Vector {
		bs := make([]*big.Int, len(args))
		for i, a := range args {
			bs[i] = big.NewInt(a)
		}
		return f134Vector{fn: fn, args: bs, want: want}
	}
	n := big.NewInt
	return []f134Vector{
		v("divmod", n(-3), -7, 2),
		v("divmod", n(-3), 7, -2),
		v("divmod", nil, 1, 0),
		v("mulDiv", n(-3), -7, 1, 2),
		v("mulDiv", nil, 1, 1, 0),
		v("percentOf", n(0), -1, 5000),
		v("percentOf", n(-1), -15000, 1),
		v("pow", nil, 2, -1),
		v("pow", n(1), 2, 0),
		v("pow", n(-8), -2, 3),
		v("pow", n(4294967296), 2, 32),
		v("pow", nil, 2, 33),
		v("pow", nil, 1, 40),
		v("sqrt", nil, -1),
		v("sqrt", n(0), 0),
		v("sqrt", n(2), 8),
		{fn: "sqrt", args: []*big.Int{p495}, want: nil, label: "sqrt(2^495)"},
		v("safediv", n(-3), -7, 2),
		v("safediv", nil, 1, 0),
		v("safemod", n(-1), -7, 2),
		v("safemod", n(1), 7, -2),
		v("safemod", nil, 1, 0),
	}
}

func (c f134Vector) name() string {
	if c.label != "" {
		return c.label
	}
	parts := make([]string, len(c.args))
	for i, a := range c.args {
		parts[i] = a.String()
	}
	return c.fn + "(" + strings.Join(parts, ",") + ")"
}

func TestF134_AnfInterpreterMathMatchesScript(t *testing.T) {
	for _, c := range f134Vectors() {
		t.Run(c.name(), func(t *testing.T) {
			args := make([]interface{}, len(c.args))
			for i, a := range c.args {
				args[i] = new(big.Int).Set(a)
			}
			if c.want == nil {
				defer func() {
					r := recover()
					if r == nil {
						t.Fatalf("script aborts; interpreter returned a value")
					}
					if _, ok := r.(*ScriptOpcodeError); !ok {
						t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", r, r)
					}
				}()
				anfEvalCall(c.fn, args, nil, nil, "probe")
				return
			}
			got, ok := anfEvalCall(c.fn, args, nil, nil, "probe").(*big.Int)
			if !ok || got.Cmp(c.want) != 0 {
				t.Fatalf("got %v, script gives %v", got, c.want)
			}
		})
	}
}

func TestF134_NativeMockMathMatchesScript(t *testing.T) {
	native := map[string]func(a []int64) int64{
		"divmod":    func(a []int64) int64 { return Divmod(a[0], a[1]) },
		"mulDiv":    func(a []int64) int64 { return MulDiv(a[0], a[1], a[2]) },
		"percentOf": func(a []int64) int64 { return PercentOf(a[0], a[1]) },
		"pow":       func(a []int64) int64 { return Pow(a[0], a[1]) },
		"sqrt":      func(a []int64) int64 { return Sqrt(a[0]) },
		"safediv":   func(a []int64) int64 { return Safediv(a[0], a[1]) },
		"safemod":   func(a []int64) int64 { return Safemod(a[0], a[1]) },
	}
	for _, c := range f134Vectors() {
		if c.label != "" {
			continue // no int64 spelling of 2^495; the int64 mock cannot reach it
		}
		t.Run(c.name(), func(t *testing.T) {
			args := make([]int64, len(c.args))
			for i, a := range c.args {
				args[i] = a.Int64()
			}
			if c.want == nil {
				defer func() {
					if recover() == nil {
						t.Fatalf("script aborts; mock returned a value")
					}
				}()
				native[c.fn](args)
				return
			}
			if got := native[c.fn](args); got != c.want.Int64() {
				t.Fatalf("got %d, script gives %d", got, c.want.Int64())
			}
		})
	}
}
