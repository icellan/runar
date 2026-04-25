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

    @Test
    void identityIsReferentiallyStable() {
        // The pass returns the same program reference when there is nothing
        // to do — callers can rely on identity semantics for caching.
        AnfProgram in = singleMethod("m", List.of(bind("t0", new LoadParam("x"))));
        assertSame(in, AnfOptimize.run(in));
    }
}
