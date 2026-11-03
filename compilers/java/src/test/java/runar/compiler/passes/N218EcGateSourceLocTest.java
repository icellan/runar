package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.ast.SourceLocation;

/**
 * N-218: port of F-343 to this tier.
 *
 * <p>The TS reference's {@code optimizeBodyOnce}
 * (packages/runar-compiler/src/optimizer/anf-ec.ts) keeps the rewritten
 * binding's source location on every helper binding a rule mints — the
 * N-104 operand gate, the N-251 neg-cancel gate, and the fused-scalar
 * helper — because stack lowering maps opcodes through
 * {@code binding.sourceLoc}. Before this fix, {@code optimizeEcMethod}
 * appended every helper binding with {@code sourceLoc == null} regardless
 * of the rewritten binding's own location, so none of a rewritten EC
 * call's gate opcodes reached the source map.
 *
 * <p>Proves: a located {@code ecMul(p, 0)} rewrite's mul gate (5 bindings),
 * a located {@code ecAdd(p, ecNegate(p))} rewrite's neg-cancel gate (7
 * bindings), and a located nested-{@code ecMul} fusion's {@code _k} helper
 * all carry the rewritten binding's {@code sourceLoc}; an unlocated
 * rewrite mints unlocated helpers (no {@code sourceLoc} invented from
 * nothing).
 *
 * <p>Does not prove: exact file/line/column assignment upstream in the ANF
 * lowerer, or end-to-end script-map behavior — that is covered by the TS
 * test f343-ec-optimizer-source-loc.test.ts and by conformance, which
 * strips {@code sourceLoc} as debug-only and so cannot regress from this
 * change.
 */
class N218EcGateSourceLocTest {

    private static final SourceLocation LOC = new SourceLocation("T.runar.ts", 7, 4);

    private static AnfProgram program(List<AnfBinding> body) {
        return new AnfProgram("Test", List.of(),
            List.of(new AnfMethod("test", List.<AnfParam>of(), body, true)));
    }

    private static AnfBinding find(List<AnfBinding> body, String name) {
        return body.stream().filter(b -> b.name().equals(name)).findFirst()
            .orElseThrow(() -> new AssertionError("missing binding " + name + " in " + body));
    }

    @Test
    void rule4MulGateCarriesSourceLoc() {
        List<AnfBinding> body = List.of(
            new AnfBinding("p", new LoadParam("pt"), null),
            new AnfBinding("zero", new LoadConst(new BigIntConst(BigInteger.ZERO)), null),
            new AnfBinding("t", new Call("ecMul", List.of("p", "zero")), LOC),
            new AnfBinding("a", new Assert("t"), null));
        List<AnfBinding> out = AnfOptimize.run(program(body)).methods().get(0).body();
        for (String name : List.of("t_inf", "t_isinf", "t_oncurve", "t_ok", "t_gate")) {
            assertEquals(LOC, find(out, name).sourceLoc(), name + ": sourceLoc mismatch");
        }
        assertEquals(LOC, find(out, "t").sourceLoc(), "t: sourceLoc mismatch");
    }

    @Test
    void rule8NegCancelGateCarriesSourceLoc() {
        List<AnfBinding> body = List.of(
            new AnfBinding("p", new LoadParam("pt"), null),
            new AnfBinding("n", new Call("ecNegate", List.of("p")), null),
            new AnfBinding("t", new Call("ecAdd", List.of("p", "n")), LOC),
            new AnfBinding("a", new Assert("t"), null));
        List<AnfBinding> out = AnfOptimize.run(program(body)).methods().get(0).body();
        for (String name : List.of("t_px", "t_py", "t_zero", "t_pxz", "t_pynz", "t_ok", "t_gate")) {
            assertEquals(LOC, find(out, name).sourceLoc(), name + ": sourceLoc mismatch");
        }
    }

    @Test
    void rule9FusedScalarHelperCarriesSourceLoc() {
        List<AnfBinding> body = List.of(
            new AnfBinding("p", new LoadParam("pt"), null),
            new AnfBinding("k1", new LoadConst(new BigIntConst(BigInteger.valueOf(3))), null),
            new AnfBinding("k2", new LoadConst(new BigIntConst(BigInteger.valueOf(5))), null),
            new AnfBinding("inner", new Call("ecMul", List.of("p", "k1")), null),
            new AnfBinding("outer", new Call("ecMul", List.of("inner", "k2")), LOC),
            new AnfBinding("a", new Assert("outer"), null));
        List<AnfBinding> out = AnfOptimize.run(program(body)).methods().get(0).body();
        assertEquals(LOC, find(out, "outer_k").sourceLoc(), "outer_k: sourceLoc mismatch");
        assertEquals(LOC, find(out, "outer").sourceLoc(), "outer: sourceLoc mismatch");
    }

    @Test
    void unlocatedRewriteMintsUnlocatedHelpers() {
        List<AnfBinding> body = List.of(
            new AnfBinding("p", new LoadParam("pt"), null),
            new AnfBinding("zero", new LoadConst(new BigIntConst(BigInteger.ZERO)), null),
            new AnfBinding("t", new Call("ecMul", List.of("p", "zero")), null),
            new AnfBinding("a", new Assert("t"), null));
        List<AnfBinding> out = AnfOptimize.run(program(body)).methods().get(0).body();
        for (AnfBinding b : out) {
            assertNull(b.sourceLoc(), b.name() + ": expected no sourceLoc");
        }
    }
}
