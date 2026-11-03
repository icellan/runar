package frontend

import (
	"os"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// F-303 (CX-GAP-001) — several comments in the Go optimizer pipeline claimed
// dead-code elimination (DCE) is a standalone pass, or that FoldConstants
// itself runs it: dce.go called itself "the canonical, standalone DCE pass
// for the Go compiler", constant_fold.go's FoldConstants doc said it "Also
// runs dead binding elimination afterward", and constant_fold_test.go's
// foldAndEliminate helper described itself as "mirroring the full pipeline
// behavior". None of that is true: the only production call to
// EliminateDeadBindings is inside OptimizeEC's optimizeMethodEC, gated by
// `if anyChanged` (anf_optimize.go) — i.e. only when some method in the
// program actually underwent an EC rewrite. FoldConstants (constant_fold.go)
// never calls it at all, and the test helper calls it UNCONDITIONALLY for
// every method, which is not what CompileFromProgram does for a program with
// no EC calls.
//
// Per the dispatcher's pre-verification: wiring EliminateDeadCode in
// unconditionally is NOT a safe drop-in here — it breaks 11 conformance
// fixtures until N-140's liveness work lands (R-194 measured the identical
// TS architecture; see packages/runar-compiler/src/__tests__/r194-dce-invocation.test.ts).
// So the fix here is documentation-only: correct every comment that
// overclaims, and pin the TRUE current behaviour so the claim cannot
// silently drift back. This mirrors F-275, which did the same thing for the
// Java tier.
//
// What this test proves: the misleading comments are gone from dce.go,
// constant_fold.go and constant_fold_test.go; the anyChanged gate still
// precedes the only production DCE call; and CompileFromProgram's exact
// two-call composition (FoldConstants then OptimizeEC, reproduced here via
// f303RunProductionPipeline) leaves a non-EC program's dead pure binding in
// place while removing it from an EC-rewritten program.
//
// What this test does NOT prove: that leaving non-EC programs un-DCE'd is
// desirable, or that the EC-gate criterion is the right one — those are
// N-140 / R-194's open questions, not this item's.

// -----------------------------------------------------------------
// Part A: the misleading comments must be gone (RED at HEAD — these
// phrases are present today in dce.go, constant_fold.go and
// constant_fold_test.go).
// -----------------------------------------------------------------

func f303ReadSource(t *testing.T, relativePath string) string {
	t.Helper()
	data, err := os.ReadFile(relativePath)
	if err != nil {
		t.Fatalf("reading %s: %v (run this test from compilers/go/frontend)", relativePath, err)
	}
	return string(data)
}

func TestF303_DceHeaderNoLongerClaimsStandalonePipelinePass(t *testing.T) {
	src := f303ReadSource(t, "dce.go")
	if strings.Contains(src, "canonical, standalone DCE pass") {
		t.Fatal("dce.go's header still calls itself a standalone DCE pass; its only " +
			"caller is OptimizeEC's optimizeMethodEC, reached only after the " +
			"anyChanged gate in anf_optimize.go")
	}
}

func TestF303_DceHeaderNamesItsOnlyCaller(t *testing.T) {
	src := f303ReadSource(t, "dce.go")
	if !strings.Contains(src, "optimizeMethodEC") {
		t.Fatal("dce.go's header should name optimizeMethodEC as the only caller, " +
			"so a reader does not have to grep for it")
	}
}

func TestF303_FoldConstantsNoLongerClaimsItRunsDce(t *testing.T) {
	src := f303ReadSource(t, "constant_fold.go")
	if strings.Contains(src, "Also runs dead binding elimination afterward") {
		t.Fatal("FoldConstants' doc comment still claims it runs dead binding " +
			"elimination afterward; FoldConstants is just `return foldConstantsOnly(program)` " +
			"— zero DCE")
	}
}

func TestF303_TestHelperCommentNoLongerClaimsItMirrorsTheFullPipeline(t *testing.T) {
	src := f303ReadSource(t, "constant_fold_test.go")
	if strings.Contains(src, "mirroring the full pipeline behavior") {
		t.Fatal("foldAndEliminate's comment claims it mirrors the full pipeline " +
			"behavior, but it calls eliminateDeadBindings UNCONDITIONALLY for every " +
			"method; the real pipeline (OptimizeEC) only does so when anyChanged — " +
			"an EC rewrite actually fired")
	}
}

// -----------------------------------------------------------------
// Part B: positional tripwire. The anyChanged gate must still exist, and
// the DCE delegation call must still be positioned AFTER it (inside
// optimizeMethodEC). This does not go red today; it is a guard for the
// next person who tries to "fix" F-303 by moving the call ahead of the
// gate, which (per R-194's TS measurement) breaks compilation of 11
// conformance fixtures until N-140 lands.
// -----------------------------------------------------------------

func TestF303_AnyChangedGateStillPrecedesTheDceDelegationCall(t *testing.T) {
	src := f303ReadSource(t, "anf_optimize.go")
	gate := strings.Index(src, "if anyChanged {")
	call := strings.Index(src, "EliminateDeadBindings(method)")
	if gate == -1 {
		t.Fatal("the `if anyChanged` early-exit gate is gone from anf_optimize.go")
	}
	if call == -1 {
		t.Fatal("optimizeMethodEC no longer delegates to EliminateDeadBindings")
	}
	if call < gate {
		t.Fatal("the DCE delegation call moved ahead of the anyChanged gate — per " +
			"R-194's TS measurement this breaks compilation of non-EC fixtures unless " +
			"DCE's own liveness model is fixed first (N-140)")
	}
}

// -----------------------------------------------------------------
// Part C: behavioural pin — documents the TRUE current behaviour of the
// production entry point's pass composition (CompileFromProgram in
// compilers/go/compiler/compiler.go calls frontend.FoldConstants then
// frontend.OptimizeEC, in that order, with default options). Reproduced
// here at the frontend-package level since compiler.go cannot be imported
// from this package without a cycle. Passes both before and after the
// comment fix; it is not the red test, it is what makes the corrected
// comments honest.
// -----------------------------------------------------------------

// f303RunProductionPipeline reproduces CompileFromProgram's exact two-call
// composition (compiler.go: FoldConstants then OptimizeEC, both enabled by
// default) without requiring the compiler package.
func f303RunProductionPipeline(program *ir.ANFProgram) *ir.ANFProgram {
	program = FoldConstants(program)
	program = OptimizeEC(program)
	return program
}

// What this proves: a non-EC program's unused, side-effect-free binding
// survives the production pipeline composition today — exactly what the
// (now corrected) comments say, and exactly the CX-GAP-001 gap.
//
// What this does NOT prove: that this is desirable behaviour, or that
// fixing it (making DCE run unconditionally) is safe — R-194's TS
// measurement says the opposite without further work on DCE's liveness
// model (N-140).
func TestF303_NonEcProgramKeepsDeadBindingThroughProductionPipeline(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadParamBinding("x", "x"),
		loadConstBigInt("deadConst", 7), // unused, pure — must survive
		callBinding("h", "hash160", []string{"x"}),
		assertBinding("a", "h"),
	}
	out := getMethodBody(f303RunProductionPipeline(makeTestProgram(bindings)))

	if len(out) != len(bindings) {
		t.Fatalf("expected no bindings removed from a non-EC program; got %d of %d",
			len(out), len(bindings))
	}
	if findBinding(out, "deadConst") == nil {
		t.Fatal("the dead, unused, pure binding must survive — the production " +
			"pipeline runs no standalone DCE for a program with no EC rewrite")
	}
}

// Control: an EC-containing program DOES get the dead binding removed, via
// OptimizeEC's EC-gated post-cleanup. This is the asymmetry the corrected
// comments describe: DCE runs ONLY when the anyChanged gate fires.
func TestF303_EcProgramRemovesDeadBindingViaEcGatedCleanup(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadParamBinding("p", "p"),
		loadConstBigInt("one", 1),
		loadConstBigInt("deadConst", 99), // unused, pure — must be removed
		callBinding("doubled", "ecMul", []string{"p", "one"}),
		assertBinding("a", "doubled"),
	}
	out := getMethodBody(f303RunProductionPipeline(makeTestProgram(bindings)))

	if findBinding(out, "deadConst") != nil {
		t.Fatal("an EC-containing method's unused pure binding must be removed by " +
			"the EC-gated cleanup (ec-mul-one rewrites ecMul(p, 1) to p, firing " +
			"anyChanged, which runs EliminateDeadBindings)")
	}
	if findBinding(out, "doubled") == nil {
		t.Fatal("the rewritten binding must survive (referenced by the assert)")
	}
}
