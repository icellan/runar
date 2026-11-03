package frontend

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// N-251: R8/R8r (ecAdd(q, ecNegate(q)) -> O and its mirror) must keep the
// adder's y = 0 doubling abort (N-110), as the gate
// assert(ecPointX(q) === 0 || ecPointY(q) !== 0) ahead of the INFINITY binding
// (user decision R96, the "gate" on both rules in optimizer/ec-rules.json).
//
// This pins the exact gate bindings — names, kinds, operands and order — that
// every tier must emit, so the seven tiers stay ANF- and hex-identical. It does
// NOT prove the gate's script semantics, which are executed on the real Spend
// engine, in both optimizer modes, by
// packages/runar-testing/src/__tests__/n251-ec-negate-cancel-y0.test.ts.

var n251Gate = []string{
	"t_px = call ecPointX p",
	"t_py = call ecPointY p",
	"t_zero = const 0",
	"t_pxz = bin_op === t_px t_zero",
	"t_pynz = bin_op !== t_py t_zero",
	"t_ok = bin_op || t_pxz t_pynz",
	"t_gate = assert t_ok",
}

func TestN251_ECNegateCancelKeepsYZeroAbort(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
	}{
		{"ec-add-negate-cancel", []string{"p", "n"}},
		{"ec-add-negate-cancel-reversed", []string{"n", "p"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := []ir.ANFBinding{
				loadParamBinding("p", "pt"),
				callBinding("n", "ecNegate", []string{"p"}),
				callBinding("t", "ecAdd", c.args),
				assertBinding("a", "t"),
			}
			want := append(append([]string{"p = load_param pt", "n = call ecNegate p"}, n251Gate...), "t = const INFINITY", "a = assert t")
			got := n104Body(getMethodBody(OptimizeEC(makeTestProgram(body))))
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("optimized body:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
			}
		})
	}
}
