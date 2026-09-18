package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;

/**
 * Unit tests for {@link AnfOptimize}.
 *
 * <p>Per the comment in {@code AnfOptimize.run}, this pass is currently an
 * identity transformation: the TypeScript / Python references do not run
 * generic alias propagation or dead-binding elimination at this stage of
 * the pipeline, and removing alias bindings would diverge from the
 * canonical ANF. These tests verify the identity contract.
 */
class AnfOptimizeTest {

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

    @Test
    void identityPreservesAliasBindings() {
        // result -> @ref:t2 must NOT be inlined / DCE'd.
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("a")));
        in.add(bind("t1", new LoadParam("b")));
        in.add(bind("t2", new BinOp("t0", "+", "t1", "bigint")));
        in.add(bind("result", new LoadConst(new BytesConst("@ref:t2"))));
        in.add(bind("t3", new Call("p256OnCurve", List.of("result"))));
        in.add(bind("t4", new Assert("t3")));

        AnfProgram out = AnfOptimize.run(singleMethod("verify", in));
        List<AnfBinding> body = bodyOf(out);

        assertEquals(in.size(), body.size(), "no bindings should be removed");
        for (int i = 0; i < in.size(); i++) {
            assertEquals(in.get(i).name(), body.get(i).name(),
                "binding " + i + " name preserved");
        }
    }

    @Test
    void identityPreservesIfWrappers() {
        // If wrappers must not be spliced away even when one branch is empty.
        List<AnfBinding> thenBranch = List.of(bind("t1", new LoadConst(new BigIntConst(BigInteger.ONE))));
        List<AnfBinding> elseBranch = List.of();

        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("cond")));
        in.add(bind("ifresult", new If("t0", thenBranch, elseBranch)));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        List<AnfBinding> body = bodyOf(out);

        assertEquals(in.size(), body.size());
        assertEquals("ifresult", body.get(1).name());
    }

    @Test
    void identityPreservesUnreferencedBindings() {
        // Unused bindings must NOT be removed at this stage.
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("x")));
        in.add(bind("t1", new LoadConst(new BigIntConst(BigInteger.valueOf(42))))); // unused
        in.add(bind("t2", new Call("hash160", List.of("t0"))));
        in.add(bind("t3", new Assert("t2")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        assertEquals(in.size(), bodyOf(out).size(), "unused bindings preserved");
    }

    /**
     * R-034 / CL-BUG-028 — {@code ec-add-negate-cancel-reversed}.
     *
     * <p>{@code optimizer/ec-rules.json} declares BOTH operand orders of the
     * negate-cancel rule with no {@code "supported"} tag, so both are required
     * in every tier. The Go engine is data-driven off that JSON and performed
     * both; the six hand-ported tiers — Java among them — implemented only
     * {@code ecAdd(x, ecNegate(x))}, so the same ANF compiled to a 1808-byte
     * script in Go and a 26140-byte one here.
     *
     * <p>The rule is unreachable from SOURCE in every tier (pass 04 gives each
     * occurrence of a variable its own binding, so {@code $x} binds to two
     * different names and no matcher unifies them). The divergence is reachable
     * through the {@code --ir} path, which accepts arbitrary ANF.
     */
    @Test
    void ecAddNegateCancelFoldsInBothOperandOrders() {
        String infinityHex = "0".repeat(128);
        String pointHex = "ab".repeat(64);

        // Control: the already-implemented forward direction.
        List<AnfBinding> forward = new ArrayList<>();
        forward.add(bind("t0", new LoadConst(new BytesConst(pointHex))));
        forward.add(bind("t1", new Call("ecNegate", List.of("t0"))));
        forward.add(bind("t2", new Call("ecAdd", List.of("t0", "t1"))));
        forward.add(bind("t3", new Assert("t2")));
        assertFoldsToInfinity(forward, infinityHex, "ecAdd(x, ecNegate(x))");

        // The direction that was missing.
        List<AnfBinding> reversed = new ArrayList<>();
        reversed.add(bind("t0", new LoadConst(new BytesConst(pointHex))));
        reversed.add(bind("t1", new Call("ecNegate", List.of("t0"))));
        reversed.add(bind("t2", new Call("ecAdd", List.of("t1", "t0"))));
        reversed.add(bind("t3", new Assert("t2")));
        assertFoldsToInfinity(reversed, infinityHex, "ecAdd(ecNegate(x), x)");
    }

    /** CONTROL: distinct points must NOT cancel — that would be a wrong answer. */
    @Test
    void ecAddOverDistinctPointsDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadConst(new BytesConst("ab".repeat(64)))));
        in.add(bind("q", new LoadConst(new BytesConst("cd".repeat(64)))));
        in.add(bind("neg", new Call("ecNegate", List.of("q"))));
        in.add(bind("t0", new Call("ecAdd", List.of("neg", "p"))));
        in.add(bind("t1", new Assert("t0")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t0");
        assertEquals(Call.class, v.getClass(), "the ecAdd must survive");
        assertEquals("ecAdd", ((Call) v).func());
    }

    private static void assertFoldsToInfinity(List<AnfBinding> in, String infinityHex, String label) {
        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t2");
        assertEquals(LoadConst.class, v.getClass(), label + " must fold to a constant");
        assertEquals(infinityHex, ((BytesConst) ((LoadConst) v).value()).hex(),
            label + " must fold to the point at infinity");
    }

    private static AnfValue findValue(AnfProgram p, String name) {
        for (AnfBinding b : bodyOf(p)) {
            if (b.name().equals(name)) return b.value();
        }
        throw new AssertionError("binding " + name + " not found");
    }

    @Test
    void identityIsReferentiallyStable() {
        // The pass returns the same program reference when there is nothing
        // to do — callers can rely on identity semantics for caching.
        AnfProgram in = singleMethod("m", List.of(bind("t0", new LoadParam("x"))));
        assertSame(in, AnfOptimize.run(in));
    }
}
