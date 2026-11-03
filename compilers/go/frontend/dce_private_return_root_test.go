package frontend

import (
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// F-108 — DCE must treat a PRIVATE method's last binding as a liveness root.
//
// Stack lowering inlines a private helper at each method_call and takes the
// helper's LAST binding as the call's result. Nothing inside the helper
// references that binding, so a pure return expression (`return n + 1n`) was
// deleted whenever DCE ran on the helper — which in this tier happens when an
// EC rewrite fires inside the helper itself. The helper was emptied and the
// contract failed to compile ("value \"t2\" not found on stack").
//
// What this proves: EliminateDeadBindings keeps a private method's final
// binding and its inputs, still drops a genuinely dead binding ahead of it,
// and still drops an unreferenced pure final binding of a PUBLIC method.
// What it does not prove: spendability — conformance/dce/private-return.test.ts
// executes the compiled script on all seven tiers.

func f108Add1Body() []ir.ANFBinding {
	return []ir.ANFBinding{
		loadConstBigInt("dead", 7),
		loadParamBinding("t0", "n"),
		loadConstBigInt("t1", 1),
		{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "+", Left: "t0", Right: "t1"}},
	}
}

func f108Names(m *ir.ANFMethod) []string {
	out := []string{}
	for _, b := range m.Body {
		out = append(out, b.Name)
	}
	return out
}

func TestF108_DCE_KeepsPrivateMethodReturnValue(t *testing.T) {
	m := ir.ANFMethod{Name: "add1", IsPublic: false, Body: f108Add1Body()}
	EliminateDeadBindings(&m)
	got := f108Names(&m)
	want := []string{"t0", "t1", "t2"}
	if len(got) != len(want) {
		t.Fatalf("DCE emptied a private helper's return value: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestF108_DCE_StillDropsPublicMethodPureLastBinding(t *testing.T) {
	m := ir.ANFMethod{Name: "pub", IsPublic: true, Body: f108Add1Body()}
	EliminateDeadBindings(&m)
	if got := f108Names(&m); len(got) != 0 {
		t.Fatalf("a public method's unreferenced pure bindings must still be eliminated, got %v", got)
	}
}
