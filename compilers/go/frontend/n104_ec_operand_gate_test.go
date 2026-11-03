package frontend

import (
	"fmt"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// N-104: the EC identity rewrites R1-R4 (ecAdd(q, O) -> q, ecAdd(O, q) -> q,
// ecMul(q, 1) -> q, ecMul(q, 0) -> O) must leave the replaced builtin's operand
// validation in place of the call. Without it a malformed or off-curve q was
// accepted by the optimized script and aborted by the unoptimized one.
//
// This pins the exact gate bindings — names, kinds, operands and order — that
// every tier must emit (see the "gate" entries in optimizer/ec-rules.json), so
// the seven tiers stay ANF- and hex-identical. It proves the Go engine emits
// the gate; it does NOT prove the gate's script semantics, which are executed
// on the real Spend engine by
// packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.

const n104FieldP = "115792089237316195423570985008687907853269984665640564039457584007908834671663"

func n104Describe(b ir.ANFBinding) string {
	v := b.Value
	switch v.Kind {
	case "load_param":
		return "load_param " + v.Name
	case "load_const":
		if v.ConstString != nil {
			s := *v.ConstString
			if s == infinityHex {
				return "const INFINITY"
			}
			if strings.HasPrefix(s, "@ref:") {
				return "ref " + s[5:]
			}
			return "const str " + s
		}
		if v.ConstBigInt != nil {
			return "const " + v.ConstBigInt.String()
		}
		return "const ?"
	case "call":
		return "call " + v.Func + " " + strings.Join(v.Args, " ")
	case "bin_op":
		s := fmt.Sprintf("bin_op %s %s %s", v.Op, v.Left, v.Right)
		if v.ResultType != "" {
			s += " " + v.ResultType
		}
		return s
	case "assert":
		return "assert " + v.ValueRef
	}
	return v.Kind
}

func n104Body(bindings []ir.ANFBinding) []string {
	out := make([]string, len(bindings))
	for i, b := range bindings {
		out[i] = b.Name + " = " + n104Describe(b)
	}
	return out
}

var n104AddGate = []string{
	"t_px = call ecPointX p",
	"t_py = call ecPointY p",
	"t_fp = const " + n104FieldP,
	"t_pxok = bin_op < t_px t_fp",
	"t_pyok = bin_op < t_py t_fp",
	"t_ok = bin_op && t_pxok t_pyok",
	"t_gate = assert t_ok",
}

var n104MulGate = []string{
	"t_inf = const INFINITY",
	"t_isinf = bin_op === p t_inf bytes",
	"t_oncurve = call ecOnCurve p",
	"t_ok = bin_op || t_isinf t_oncurve",
	"t_gate = assert t_ok",
}

func TestN104_ECOperandGate(t *testing.T) {
	cases := []struct {
		name   string
		body   []ir.ANFBinding
		expect []string
	}{
		{
			name: "ec-add-identity-right",
			body: []ir.ANFBinding{
				loadParamBinding("p", "pt"),
				loadConstHex("inf", infinityHex),
				callBinding("t", "ecAdd", []string{"p", "inf"}),
				assertBinding("a", "t"),
			},
			expect: append(append([]string{"p = load_param pt"}, n104AddGate...), "t = ref p", "a = assert t"),
		},
		{
			name: "ec-add-identity-left",
			body: []ir.ANFBinding{
				loadParamBinding("p", "pt"),
				loadConstHex("inf", infinityHex),
				callBinding("t", "ecAdd", []string{"inf", "p"}),
				assertBinding("a", "t"),
			},
			expect: append(append([]string{"p = load_param pt"}, n104AddGate...), "t = ref p", "a = assert t"),
		},
		{
			name: "ec-mul-one",
			body: []ir.ANFBinding{
				loadParamBinding("p", "pt"),
				loadConstBigInt("one", 1),
				callBinding("t", "ecMul", []string{"p", "one"}),
				assertBinding("a", "t"),
			},
			expect: append(append([]string{"p = load_param pt"}, n104MulGate...), "t = ref p", "a = assert t"),
		},
		{
			name: "ec-mul-zero",
			body: []ir.ANFBinding{
				loadParamBinding("p", "pt"),
				loadConstBigInt("zero", 0),
				callBinding("t", "ecMul", []string{"p", "zero"}),
				assertBinding("a", "t"),
			},
			expect: append(append([]string{"p = load_param pt"}, n104MulGate...), "t = const INFINITY", "a = assert t"),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := n104Body(getMethodBody(OptimizeEC(makeTestProgram(c.body))))
			if strings.Join(got, "\n") != strings.Join(c.expect, "\n") {
				t.Fatalf("optimized body:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(c.expect, "\n  "))
			}
		})
	}
}
