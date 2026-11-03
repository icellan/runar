package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;

/**
 * F-275 (CX-DOC-001 / CX-GAP-007 / GK-GAP-003) — several comments in the Java
 * optimizer pipeline claimed dead-code elimination (DCE) is a standalone pass
 * or runs unconditionally ("DCE + EC rewrite always ON", "This pass is
 * unconditional in the pipeline", "the canonical, standalone DCE pass"). None
 * of that is true: {@code AnfOptimize.run} returns the program UNCHANGED when
 * no method contains an EC intrinsic call (see {@code hasEcCalls} /
 * {@code if (!anyChanged) return program;}), and {@code Dce.eliminateDead} is
 * only ever invoked from inside {@code optimizeEcMethod}, i.e. after that
 * gate. A non-EC program therefore gets ZERO standalone dead-binding cleanup
 * from {@code Cli.optimizeAnf} today.
 *
 * <p>Per the dispatcher's pre-verification and R-194 (the identical TS
 * architecture, see {@code packages/runar-compiler/src/optimizer/dce.ts} and
 * {@code r194-dce-invocation.test.ts}): wiring DCE to run unconditionally is
 * NOT a safe drop-in here — TS measured 11/78 conformance fixtures failing to
 * COMPILE outright when the equivalent gate was removed, because stack
 * lowering still relies on bindings this DCE implementation would delete.
 * Go's {@code anf_optimize.go} and Python's {@code anf_optimize.py}
 * ({@code _has_ec_calls}) gate the same way, so this is cross-tier
 * architecture, not a Java-only defect. The fix here is therefore
 * documentation-only: correct every comment that overclaims, and pin the
 * TRUE current behaviour so the claim cannot silently drift back.
 *
 * <p>GK-GAP-003's specific mechanism claim ("an unreferenced statement-if
 * whose then-arm is assert can be deleted when DCE runs") is REJECTED for
 * Java: {@code Dce.hasSideEffect} already recurses into {@code If}/{@code
 * Loop} bodies and returns {@code true} when a nested {@code Assert} exists
 * (see {@code AnfOptimizeTest} / {@code Dce.java}), so that specific decay
 * does not reproduce today.
 */
class F275DceInvocationTest {

    // -----------------------------------------------------------------
    // Part A: the misleading comments must be gone (this is the RED test —
    // it fails at HEAD because these phrases are present today).
    // -----------------------------------------------------------------

    private static String readSource(String relativePath) throws IOException {
        Path p = Path.of(relativePath);
        assertTrue(
            Files.exists(p),
            "expected to find " + p.toAbsolutePath()
                + " — run this test from the compilers/java Gradle project dir");
        return Files.readString(p);
    }

    @Test
    void pipelineTestSupportNoLongerClaimsDceAlwaysOn() throws IOException {
        String src = readSource(
            "src/test/java/runar/compiler/passes/PipelineTestSupport.java");
        assertFalse(
            src.contains("DCE + EC rewrite always ON"),
            "PipelineTestSupport.java still claims DCE is always ON; "
                + "Cli.optimizeAnf only DCEs a method when SOME method in the "
                + "program has an EC call (AnfOptimize.run's anyChanged gate)");
    }

    @Test
    void anfOptimizeHeaderNoLongerClaimsUnconditional() throws IOException {
        String src = readSource(
            "src/main/java/runar/compiler/passes/AnfOptimize.java");
        String header = src.substring(0, src.indexOf("public final class AnfOptimize"));
        assertFalse(
            header.contains("unconditional in the pipeline"),
            "AnfOptimize.java's class javadoc claims the pass (incl. DCE) is "
                + "unconditional, contradicting run()'s own javadoc two lines "
                + "below it, which correctly says the pass is EC-gated");
    }

    @Test
    void dceHeaderNoLongerClaimsStandalonePipelinePass() throws IOException {
        String src = readSource("src/main/java/runar/compiler/passes/Dce.java");
        String header = src.substring(0, src.indexOf("public final class Dce"));
        assertFalse(
            header.contains("standalone DCE pass"),
            "Dce.java's header calls itself a standalone DCE pass; its only "
                + "caller is AnfOptimize.optimizeEcMethod, reached only after "
                + "the anyChanged/hasEcCalls gate in AnfOptimize.run");
    }

    @Test
    void dceHeaderNamesItsOnlyCaller() throws IOException {
        String src = readSource("src/main/java/runar/compiler/passes/Dce.java");
        String header = src.substring(0, src.indexOf("public final class Dce"));
        assertTrue(
            header.contains("AnfOptimize") && header.contains("optimizeEcMethod"),
            "the header should name AnfOptimize.optimizeEcMethod as the only "
                + "caller, so a reader does not have to grep for it");
    }

    // -----------------------------------------------------------------
    // Part B: positional tripwire. The EC gate must still exist, and the
    // DCE delegation call must still be positioned AFTER it (inside
    // optimizeEcMethod). This does not go red today; it is a guard for the
    // next person who tries to "fix" this by moving the call.
    // -----------------------------------------------------------------

    @Test
    void ecGateStillPrecedesTheDceDelegationCall() throws IOException {
        String src = readSource("src/main/java/runar/compiler/passes/AnfOptimize.java");
        int gate = src.indexOf("if (!anyChanged) return program;");
        // N-097 moved the call from optimizeEcMethod into run(), after the
        // gate; the literal follows it, the ordering it pins is unchanged.
        int call = src.indexOf("method.withBody(eliminateDead(method))");
        assertTrue(gate > -1, "the anyChanged early-exit gate is gone from AnfOptimize.run");
        assertTrue(call > -1, "optimizeEcMethod no longer delegates to eliminateDead");
        assertTrue(
            call > gate,
            "the DCE delegation call moved ahead of the EC gate — per R-194's "
                + "TS measurement this breaks compilation of non-EC fixtures "
                + "unless DCE's own liveness model is fixed first (N-140)");
    }

    // -----------------------------------------------------------------
    // Part C: behavioural pin — documents the TRUE current behaviour of the
    // production entry point Cli.optimizeAnf (not just AnfOptimize.run in
    // isolation). Passes both before and after the comment fix; it is not
    // the red test, it is what makes the corrected comments honest.
    // -----------------------------------------------------------------

    private static AnfBinding bind(String name, AnfValue v) {
        return new AnfBinding(name, v, null);
    }

    private static AnfProgram singleMethod(String methodName, List<AnfBinding> body) {
        AnfMethod m = new AnfMethod(methodName, List.<AnfParam>of(), body, true);
        return new AnfProgram("Test", List.of(), List.of(m));
    }

    private static List<AnfBinding> bodyOf(AnfProgram p) {
        return p.methods().get(0).body();
    }

    private static boolean hasBinding(List<AnfBinding> body, String name) {
        return body.stream().anyMatch(b -> b.name().equals(name));
    }

    /**
     * What this proves: a non-EC program's unused, side-effect-free binding
     * survives {@code Cli.optimizeAnf} end-to-end today — exactly what the
     * (now corrected) comments say, and exactly the CX-GAP-007 gap.
     *
     * <p>What this does NOT prove: that this is desirable behaviour, or that
     * fixing it (making DCE run unconditionally) is safe — R-194's TS
     * measurement says the opposite without further work on DCE's liveness
     * model (N-140).
     */
    @Test
    void nonEcProgramKeepsDeadBindingThroughProductionPipeline() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("x", new LoadParam("x")));
        in.add(bind("deadConst", new LoadConst(new BigIntConst(BigInteger.valueOf(7))))); // unused, pure
        in.add(bind("h", new Call("hash160", List.of("x"))));
        in.add(bind("a", new Assert("h")));

        AnfProgram out = Cli.optimizeAnf(singleMethod("m", in), /* disableConstantFolding */ true);
        List<AnfBinding> body = bodyOf(out);

        assertEquals(in.size(), body.size(), "no bindings should be removed from a non-EC program");
        assertTrue(hasBinding(body, "deadConst"),
            "the dead, unused, pure binding must survive — this pipeline runs no standalone DCE");
    }

    /**
     * Control: an EC-rewritten program DOES get the dead binding removed,
     * via AnfOptimize's EC-gated post-cleanup. This is the asymmetry the
     * corrected comments describe: DCE runs ONLY when the EC gate fires.
     *
     * <p>N-097 / N-195: the gate is "a rewrite rule fired" (the TS
     * reference), so the input is now one a rule fires on — ec-mul-one
     * rewrites {@code ecMul(p, 1)} to {@code p}, as Go's sibling
     * TestF303_EcProgramRemovesDeadBindingViaEcGatedCleanup does. The former
     * input (an EC call no rule fires on) is pinned the other way below.
     */
    @Test
    void ecProgramRemovesDeadBindingViaEcGatedCleanup() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadConst(new BytesConst("ab".repeat(64)))));
        in.add(bind("one", new LoadConst(new BigIntConst(BigInteger.ONE))));
        in.add(bind("deadConst", new LoadConst(new BigIntConst(BigInteger.valueOf(99))))); // unused, pure
        in.add(bind("t0", new Call("ecMul", List.of("p", "one")))); // ec-mul-one fires
        in.add(bind("t1", new Assert("t0")));

        AnfProgram out = Cli.optimizeAnf(singleMethod("m", in), /* disableConstantFolding */ true);
        List<AnfBinding> body = bodyOf(out);

        assertFalse(hasBinding(body, "deadConst"),
            "an EC-rewritten method's unused pure binding IS removed by the EC-gated cleanup");
        assertTrue(hasBinding(body, "t0"), "the rewritten binding must survive (referenced by the assert)");
    }

    /**
     * N-097 / N-195: an EC call that NO rule rewrites does not open the gate.
     * The TS reference (anf-ec.ts optimizeEC) returns such a program
     * untouched, dead bindings included; this tier used to DCE it because it
     * gated on the presence of an EC call, which moved the script bytes.
     */
    @Test
    void ecCallWithNoRewriteKeepsDeadBinding() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadConst(new BytesConst("ab".repeat(64)))));
        in.add(bind("q", new LoadConst(new BytesConst("cd".repeat(64)))));
        in.add(bind("deadConst", new LoadConst(new BigIntConst(BigInteger.valueOf(99))))); // unused, pure
        in.add(bind("neg", new Call("ecNegate", List.of("q"))));
        in.add(bind("t0", new Call("ecAdd", List.of("neg", "p")))); // distinct points: does not fold
        in.add(bind("t1", new Assert("t0")));

        AnfProgram out = Cli.optimizeAnf(singleMethod("m", in), /* disableConstantFolding */ true);
        List<AnfBinding> body = bodyOf(out);

        assertTrue(hasBinding(body, "deadConst"),
            "no rule fired, so no DCE: the dead pure binding survives, as in the TS reference");
        assertEquals(in.size(), body.size(), "no bindings should be removed when no EC rule fires");
    }
}
