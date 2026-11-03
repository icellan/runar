package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;

/**
 * F-108 — DCE must treat a PRIVATE method's last binding as a liveness root.
 *
 * <p>Stack lowering inlines a private helper at each {@code method_call} and
 * takes the helper's LAST binding as the call's result. Nothing inside the
 * helper references that binding, so a pure return expression
 * ({@code return n + 1n}) was deleted whenever DCE ran — which in this tier
 * happens to every method once any EC rewrite fires anywhere in the program.
 * The helper was emptied and the contract failed to compile ("value 't2' not
 * found on stack").
 *
 * <p>What this proves: {@link Dce#run} keeps a private method's final binding
 * and its inputs, still drops a genuinely dead binding ahead of it, and still
 * drops an unreferenced pure final binding of a PUBLIC method. What it does not
 * prove: spendability — {@code conformance/dce/private-return.test.ts} executes
 * the compiled script on all seven tiers.
 */
class F108DcePrivateReturnRootTest {

    private static AnfBinding bind(String name, AnfValue v) {
        return new AnfBinding(name, v, null);
    }

    private static AnfMethod add1(boolean isPublic) {
        List<AnfBinding> body = List.of(
            bind("dead", new LoadConst(new BigIntConst(BigInteger.valueOf(7)))),
            bind("t0", new LoadParam("n")),
            bind("t1", new LoadConst(new BigIntConst(BigInteger.ONE))),
            bind("t2", new BinOp("+", "t0", "t1", "bigint")));
        return new AnfMethod(isPublic ? "pubM" : "add1",
            List.of(new AnfParam("n", "bigint")), body, isPublic);
    }

    private static List<String> namesAfterDce(AnfMethod m) {
        AnfProgram out = Dce.run(new AnfProgram("T", List.of(), List.of(m)));
        return out.methods().get(0).body().stream().map(AnfBinding::name).toList();
    }

    @Test
    void keepsPrivateMethodReturnValue() {
        assertEquals(List.of("t0", "t1", "t2"), namesAfterDce(add1(false)),
            "DCE emptied a private helper's return value");
    }

    @Test
    void stillDropsPublicMethodPureLastBinding() {
        assertEquals(List.of(), namesAfterDce(add1(true)));
    }
}
