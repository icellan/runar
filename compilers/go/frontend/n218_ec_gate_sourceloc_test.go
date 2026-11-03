package frontend

import (
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// N-218: port of F-343 to the Go rule engine. The TS optimizer's
// optimizeBodyOnce (packages/runar-compiler/src/optimizer/anf-ec.ts) keeps
// the rewritten binding's SourceLoc on every helper binding it mints — the
// N-104 operand gate (Rules 1-4), the N-251 neg-cancel gate (Rules 8/8r), and
// the fused-scalar helper (Rules 9/10/11) — because stack lowering maps
// opcodes through binding.SourceLoc (codegen/stack.go:1502,1534). Before this
// fix, OptimizeEC left every minted helper with SourceLoc == nil, so none of
// a rewritten EC call's gate opcodes reached the source map.
//
// This test proves: for a located ecMul(p, 0) rewrite (Rule 4 / N-104 mul
// gate), a located ecAdd(q, ecNegate(q)) rewrite (Rule 8 / N-251 gate), and a
// located nested ecMul fusion (Rule 9), every minted helper binding carries
// the rewritten binding's SourceLoc, and the rewritten binding itself keeps
// it. It also proves an unlocated binding's rewrite mints unlocated helpers
// (no SourceLoc invented from nothing).
//
// It does NOT prove anything about the exact file/line/column the ANF
// lowerer assigns upstream, nor about script-map behavior end to end — that
// is covered by the TS test (f343-ec-optimizer-source-loc.test.ts) and by the
// cross-tier parity the conformance suite enforces for everything BUT
// SourceLoc (which runner.ts explicitly strips as debug-only).
func TestN218_ECGateBindingsCarrySourceLoc(t *testing.T) {
	loc := &ir.SourceLocation{File: "T.runar.ts", Line: 7, Column: 4}

	t.Run("Rule 4 ecMul(p,0): mul gate + rewritten binding all carry the loc", func(t *testing.T) {
		body := []ir.ANFBinding{
			loadParamBinding("p", "pt"),
			loadConstBigInt("zero", 0),
			func() ir.ANFBinding {
				b := callBinding("t", "ecMul", []string{"p", "zero"})
				b.SourceLoc = loc
				return b
			}(),
			assertBinding("a", "t"),
		}
		out := getMethodBody(OptimizeEC(makeTestProgram(body)))
		minted := make([]ir.ANFBinding, 0)
		for _, b := range out {
			if b.Name == "t_inf" || b.Name == "t_isinf" || b.Name == "t_oncurve" || b.Name == "t_ok" || b.Name == "t_gate" {
				minted = append(minted, b)
			}
		}
		if len(minted) != 5 {
			t.Fatalf("expected 5 minted gate bindings, got %d: %v", len(minted), bindingNames(out))
		}
		for _, m := range minted {
			if m.SourceLoc == nil || *m.SourceLoc != *loc {
				t.Errorf("gate binding %q: SourceLoc = %v, want %v", m.Name, m.SourceLoc, loc)
			}
		}
		rewritten := findBinding(out, "t")
		if rewritten == nil || rewritten.SourceLoc == nil || *rewritten.SourceLoc != *loc {
			t.Errorf("rewritten binding %q: SourceLoc = %v, want %v", "t", rewritten.SourceLoc, loc)
		}
	})

	t.Run("Rule 8 ecAdd(p, ecNegate(p)): N-251 neg-cancel gate carries the loc", func(t *testing.T) {
		body := []ir.ANFBinding{
			loadParamBinding("p", "pt"),
			callBinding("n", "ecNegate", []string{"p"}),
			func() ir.ANFBinding {
				b := callBinding("t", "ecAdd", []string{"p", "n"})
				b.SourceLoc = loc
				return b
			}(),
			assertBinding("a", "t"),
		}
		out := getMethodBody(OptimizeEC(makeTestProgram(body)))
		mintedNames := []string{"t_px", "t_py", "t_zero", "t_pxz", "t_pynz", "t_ok", "t_gate"}
		for _, name := range mintedNames {
			m := findBinding(out, name)
			if m == nil {
				t.Fatalf("expected minted gate binding %q, got body %v", name, bindingNames(out))
			}
			if m.SourceLoc == nil || *m.SourceLoc != *loc {
				t.Errorf("gate binding %q: SourceLoc = %v, want %v", name, m.SourceLoc, loc)
			}
		}
	})

	t.Run("Rule 9 fusion: the fused-scalar helper carries the loc", func(t *testing.T) {
		body := []ir.ANFBinding{
			loadParamBinding("p", "pt"),
			loadConstBigInt("k1", 3),
			loadConstBigInt("k2", 5),
			callBinding("inner", "ecMul", []string{"p", "k1"}),
			func() ir.ANFBinding {
				b := callBinding("outer", "ecMul", []string{"inner", "k2"})
				b.SourceLoc = loc
				return b
			}(),
			assertBinding("a", "outer"),
		}
		out := getMethodBody(OptimizeEC(makeTestProgram(body)))
		helper := findBinding(out, "outer_k")
		if helper == nil {
			t.Fatalf("expected minted fused-scalar helper outer_k, got body %v", bindingNames(out))
		}
		if helper.SourceLoc == nil || *helper.SourceLoc != *loc {
			t.Errorf("helper outer_k: SourceLoc = %v, want %v", helper.SourceLoc, loc)
		}
		rewritten := findBinding(out, "outer")
		if rewritten == nil || rewritten.SourceLoc == nil || *rewritten.SourceLoc != *loc {
			t.Errorf("rewritten binding outer: SourceLoc = %v, want %v", rewritten.SourceLoc, loc)
		}
	})

	t.Run("unlocated binding stays unlocated: no SourceLoc invented", func(t *testing.T) {
		body := []ir.ANFBinding{
			loadParamBinding("p", "pt"),
			loadConstBigInt("zero", 0),
			callBinding("t", "ecMul", []string{"p", "zero"}), // no SourceLoc set
			assertBinding("a", "t"),
		}
		out := getMethodBody(OptimizeEC(makeTestProgram(body)))
		for _, b := range out {
			if b.SourceLoc != nil {
				t.Errorf("binding %q: expected nil SourceLoc, got %v", b.Name, b.SourceLoc)
			}
		}
	})
}
