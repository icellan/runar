package compiler

import (
	"strings"
	"testing"
)

// F-071 (CL-BUG-009) — recursion supplied through `--ir`.
//
// frontend.Validate's checkNoRecursion runs only on the CompileFromSource*
// paths. On the IR paths stack lowering inlines every method_call to a private
// method by lowering its body in place (codegen/stack.go inlineMethodCall),
// with no cycle or depth guard. A private method whose body calls itself, or a
// pair that call each other, re-enters inlineMethodCall without bound and the
// process dies with `fatal error: stack overflow` — a Go runtime fatal that no
// recover() in the pipeline can catch.
//
// What this proves: CompileFromIRBytes (the function behind `runar-go --ir`)
// returns an ordinary error naming a method on the cycle, with the frontend's
// "recursion detected" wording, for direct self-recursion and for mutual
// recursion; and a non-recursive diamond (two helpers sharing a third) still
// compiles, so the check is a cycle check and not a "called twice" check.
//
// What this does NOT prove: anything about the other six tiers' --ir paths,
// or about recursion through anything other than method_call (the only ANF
// node stack lowering inlines).

// recursionIR builds a program whose public `unlock(x)` calls private `p(x)`
// and asserts its result. Each privateMethods entry is {method, callee}: the
// method returns callee(x), or x + 1 when callee is "".
func recursionIR(name string, privateMethods [][2]string) string {
	var b strings.Builder
	b.WriteString(`{"contractName": "` + name + `", "properties": [], "methods": [`)
	b.WriteString(`{"name": "unlock", "isPublic": true, "params": [{"name": "x", "type": "bigint"}], "body": [
		{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
		{"name": "t1", "value": {"kind": "load_param", "name": "x"}},
		{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "p", "args": ["t1"]}},
		{"name": "t3", "value": {"kind": "load_const", "value": 7}},
		{"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t2", "right": "t3"}},
		{"name": "t5", "value": {"kind": "assert", "value": "t4"}}
	]}`)
	for _, pm := range privateMethods {
		method, callee := pm[0], pm[1]
		b.WriteString(`, {"name": "` + method + `", "isPublic": false, "params": [{"name": "x", "type": "bigint"}], "body": [`)
		if callee == "" {
			b.WriteString(`
				{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
				{"name": "t1", "value": {"kind": "load_const", "value": 1}},
				{"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}}`)
		} else {
			b.WriteString(`
				{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "x"}},
				{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "` + callee + `", "args": ["t1"]}}`)
		}
		b.WriteString(`]}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestF071_IRRecursionRefused(t *testing.T) {
	cases := []struct {
		name    string
		methods [][2]string
		cycleOn []string // any of these may be named
	}{
		{"direct", [][2]string{{"p", "p"}}, []string{"p"}},
		{"mutual", [][2]string{{"p", "q"}, {"q", "p"}}, []string{"p", "q"}},
		// The cycle sits BELOW the first helper: p -> q -> r -> q.
		{"deep", [][2]string{{"p", "q"}, {"q", "r"}, {"r", "q"}}, []string{"q", "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileFromIRBytes([]byte(recursionIR("Rec", tc.methods)))
			if err == nil {
				t.Fatalf("expected a recursion refusal, got a compiled artifact")
			}
			msg := err.Error()
			if !strings.Contains(msg, "recursion detected") || !strings.Contains(msg, "calls itself directly or indirectly") {
				t.Fatalf("expected the frontend's recursion diagnostic, got: %v", err)
			}
			named := false
			for _, m := range tc.cycleOn {
				if strings.Contains(msg, "method '"+m+"'") {
					named = true
				}
			}
			if !named {
				t.Fatalf("diagnostic must name a method on the cycle %v, got: %v", tc.cycleOn, err)
			}
		})
	}
}

// Controls: a non-recursive helper chain (p -> q -> r) and a diamond
// (unlock -> a -> c, unlock -> b -> c) must still compile — c is reached
// twice but there is no cycle.
func TestF071_IRNonRecursiveDiamondAccepted(t *testing.T) {
	ir := recursionIR("Chain", [][2]string{{"p", "q"}, {"q", "r"}, {"r", ""}})
	if _, err := CompileFromIRBytes([]byte(ir)); err != nil {
		t.Fatalf("non-recursive helper chain must compile, got: %v", err)
	}

	twoSites := `{"contractName": "TwoSites", "properties": [], "methods": [
		{"name": "unlock", "isPublic": true, "params": [{"name": "x", "type": "bigint"}], "body": [
			{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
			{"name": "t1", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "a", "args": ["t1"]}},
			{"name": "t3", "value": {"kind": "load_const", "value": "@this"}},
			{"name": "t4", "value": {"kind": "method_call", "object": "t3", "method": "b", "args": ["t2"]}},
			{"name": "t5", "value": {"kind": "load_const", "value": 9}},
			{"name": "t6", "value": {"kind": "bin_op", "op": "===", "left": "t4", "right": "t5"}},
			{"name": "t7", "value": {"kind": "assert", "value": "t6"}}
		]},
		{"name": "a", "isPublic": false, "params": [{"name": "x", "type": "bigint"}], "body": [
			{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
			{"name": "t1", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "c", "args": ["t1"]}}
		]},
		{"name": "b", "isPublic": false, "params": [{"name": "x", "type": "bigint"}], "body": [
			{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
			{"name": "t1", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "c", "args": ["t1"]}}
		]},
		{"name": "c", "isPublic": false, "params": [{"name": "x", "type": "bigint"}], "body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t1", "value": {"kind": "load_const", "value": 1}},
			{"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}}
		]}
	]}`
	if _, err := CompileFromIRBytes([]byte(twoSites)); err != nil {
		t.Fatalf("diamond (a->c, b->c) must compile, got: %v", err)
	}
}
