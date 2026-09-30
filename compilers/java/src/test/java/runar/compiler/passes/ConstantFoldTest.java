package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;

/**
 * Unit tests for {@link ConstantFold}.
 *
 * <p>Each test hand-builds an ANF method with the smallest possible body
 * that exercises the rule under test, runs the pass, and asserts both the
 * shape of the resulting binding and that the original side-effecting
 * bindings remain untouched.
 */
class ConstantFoldTest {

    // ---------------------------------------------------------------
    // Builders
    // ---------------------------------------------------------------

    private static AnfBinding bind(String name, AnfValue v) {
        return new AnfBinding(name, v, null);
    }

    private static AnfBinding bigIntConst(String name, long v) {
        return bind(name, new LoadConst(new BigIntConst(BigInteger.valueOf(v))));
    }

    private static AnfBinding boolConst(String name, boolean v) {
        return bind(name, new LoadConst(new BoolConst(v)));
    }

    private static AnfBinding bytesConst(String name, String hex) {
        return bind(name, new LoadConst(new BytesConst(hex)));
    }

    private static AnfProgram singleMethodProgram(List<AnfBinding> body) {
        AnfMethod m = new AnfMethod("test", List.<AnfParam>of(), body, true);
        return new AnfProgram("Test", List.of(), List.of(m));
    }

    private static AnfMethod soleMethod(AnfProgram p) {
        return p.methods().get(0);
    }

    private static AnfBinding findBinding(AnfMethod m, String name) {
        for (AnfBinding b : m.body()) {
            if (b.name().equals(name)) return b;
        }
        throw new AssertionError("no binding " + name);
    }

    private static BigInteger bigInt(AnfValue v) {
        assertTrue(v instanceof LoadConst);
        LoadConst lc = (LoadConst) v;
        assertTrue(lc.value() instanceof BigIntConst, "expected BigIntConst, got " + lc.value());
        return ((BigIntConst) lc.value()).value();
    }

    private static boolean boolVal(AnfValue v) {
        assertTrue(v instanceof LoadConst);
        LoadConst lc = (LoadConst) v;
        assertTrue(lc.value() instanceof BoolConst, "expected BoolConst, got " + lc.value());
        return ((BoolConst) lc.value()).value();
    }

    private static String hex(AnfValue v) {
        assertTrue(v instanceof LoadConst);
        LoadConst lc = (LoadConst) v;
        assertTrue(lc.value() instanceof BytesConst, "expected BytesConst, got " + lc.value());
        return ((BytesConst) lc.value()).hex();
    }

    // ---------------------------------------------------------------
    // Arithmetic folding
    // ---------------------------------------------------------------

    @Test
    void foldsAddition() {
        // t0=2, t1=3, t2 = t0 + t1  ->  t2 = 5
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 2),
            bigIntConst("t1", 3),
            bind("t2", new BinOp("+", "t0", "t1", null))
        );
        AnfProgram out = ConstantFold.run(singleMethodProgram(body));
        assertEquals(BigInteger.valueOf(5), bigInt(findBinding(soleMethod(out), "t2").value()));
    }

    @Test
    void foldsChainedArithmetic() {
        // t0=10, t1=2, t2=t0-t1, t3=t2*t1, t4=t3/t1  -> all fold
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 10),
            bigIntConst("t1", 2),
            bind("t2", new BinOp("-", "t0", "t1", null)),
            bind("t3", new BinOp("*", "t2", "t1", null)),
            bind("t4", new BinOp("/", "t3", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(BigInteger.valueOf(8), bigInt(findBinding(m, "t2").value()));
        assertEquals(BigInteger.valueOf(16), bigInt(findBinding(m, "t3").value()));
        assertEquals(BigInteger.valueOf(8), bigInt(findBinding(m, "t4").value()));
    }

    @Test
    void doesNotFoldDivisionByZero() {
        // t0=5, t1=0, t2 = t0 / t1  ->  unchanged
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 5),
            bigIntConst("t1", 0),
            bind("t2", new BinOp("/", "t0", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "t2").value() instanceof BinOp);
    }

    @Test
    void foldsRemainderSignsLikeJsBigInt() {
        // (-7) % 3 -> -1 (sign follows dividend), matching the Python
        // and Go reference behaviour.
        List<AnfBinding> body = List.of(
            bigIntConst("t0", -7),
            bigIntConst("t1", 3),
            bind("t2", new BinOp("%", "t0", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(BigInteger.valueOf(-1), bigInt(findBinding(m, "t2").value()));
    }

    @Test
    void foldsTruncatedDivision() {
        // (-7) / 2 -> -3 (truncation toward zero)
        List<AnfBinding> body = List.of(
            bigIntConst("t0", -7),
            bigIntConst("t1", 2),
            bind("t2", new BinOp("/", "t0", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(BigInteger.valueOf(-3), bigInt(findBinding(m, "t2").value()));
    }

    // ---------------------------------------------------------------
    // Comparison folding
    // ---------------------------------------------------------------

    @Test
    void foldsComparisonOperators() {
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 5),
            bigIntConst("t1", 3),
            bind("eq", new BinOp("===", "t0", "t1", null)),
            bind("ne", new BinOp("!==", "t0", "t1", null)),
            bind("lt", new BinOp("<", "t0", "t1", null)),
            bind("ge", new BinOp(">=", "t0", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(false, boolVal(findBinding(m, "eq").value()));
        assertEquals(true, boolVal(findBinding(m, "ne").value()));
        assertEquals(false, boolVal(findBinding(m, "lt").value()));
        assertEquals(true, boolVal(findBinding(m, "ge").value()));
    }

    // ---------------------------------------------------------------
    // Bitwise folding
    // ---------------------------------------------------------------

    @Test
    void doesNotFoldBitwiseAndOrXor() {
        // OP_AND/OP_OR/OP_XOR operate on the operands' raw script-number bytes
        // and require equal length — the numeric fold (12 & 10 == 8) disagrees
        // with the on-chain result (e.g. 255 & 1 ABORTS on a length mismatch).
        // Never fold; leave the bin_ops for the runtime opcode.
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 12),
            bigIntConst("t1", 10),
            bind("a", new BinOp("&", "t0", "t1", null)),
            bind("o", new BinOp("|", "t0", "t1", null)),
            bind("x", new BinOp("^", "t0", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "a").value() instanceof BinOp);
        assertTrue(findBinding(m, "o").value() instanceof BinOp);
        assertTrue(findBinding(m, "x").value() instanceof BinOp);
    }

    @Test
    void doesNotFoldShiftsAndBitNot() {
        // OP_LSHIFT/OP_RSHIFT/OP_INVERT are byte-array ops: 255 << 1 is 254
        // on-chain (not 510) and ~5 is -122 (not -6). Native BigInteger folding
        // would bake a wrong constant into the deployed script, so leave these
        // as bin_op/unary_op for the runtime opcode.
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 5),
            bigIntConst("t1", 2),
            bind("shl", new BinOp("<<", "t0", "t1", null)),
            bind("shr", new BinOp(">>", "t0", "t1", null)),
            bind("neg", new UnaryOp("~", "t0", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "shl").value() instanceof BinOp);
        assertTrue(findBinding(m, "shr").value() instanceof BinOp);
        assertTrue(findBinding(m, "neg").value() instanceof UnaryOp);
    }

    @Test
    void doesNotFoldShiftsWithNegativeLeftOperand() {
        // BSV shifts are logical; folding a negative left would silently
        // change semantics. Reference compilers leave the binding alone.
        List<AnfBinding> body = List.of(
            bigIntConst("t0", -5),
            bigIntConst("t1", 2),
            bind("shl", new BinOp("<<", "t0", "t1", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "shl").value() instanceof BinOp);
    }

    // ---------------------------------------------------------------
    // Boolean folding (incl. short-circuit on literals)
    // ---------------------------------------------------------------

    @Test
    void foldsBooleanShortCircuit() {
        // true && false -> false, true || false -> true, !true -> false
        List<AnfBinding> body = List.of(
            boolConst("t0", true),
            boolConst("t1", false),
            bind("and", new BinOp("&&", "t0", "t1", null)),
            bind("or",  new BinOp("||", "t0", "t1", null)),
            bind("not", new UnaryOp("!", "t0", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(false, boolVal(findBinding(m, "and").value()));
        assertEquals(true,  boolVal(findBinding(m, "or").value()));
        assertEquals(false, boolVal(findBinding(m, "not").value()));
    }

    // ---------------------------------------------------------------
    // ByteString concatenation
    // ---------------------------------------------------------------

    @Test
    void foldsHexByteStringConcat() {
        // "ab" + "cd" -> "abcd"
        List<AnfBinding> body = List.of(
            bytesConst("t0", "ab"),
            bytesConst("t1", "cd"),
            bind("t2", new BinOp("+", "t0", "t1", "bytes"))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals("abcd", hex(findBinding(m, "t2").value()));
    }

    @Test
    void doesNotFoldNonHexByteStringConcat() {
        // Non-hex strings should NOT be concatenated — matches Python ref.
        List<AnfBinding> body = List.of(
            bytesConst("t0", "hello"),
            bytesConst("t1", "world"),
            bind("t2", new BinOp("+", "t0", "t1", "bytes"))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "t2").value() instanceof BinOp);
    }

    // ---------------------------------------------------------------
    // Builtin math calls
    // ---------------------------------------------------------------

    @Test
    void foldsPureMathBuiltins() {
        // abs(-7) -> 7; max(2,5) -> 5; pow(2,10) -> 1024
        List<AnfBinding> body = new ArrayList<>(List.of(
            bigIntConst("a", -7),
            bigIntConst("b", 2),
            bigIntConst("c", 5),
            bigIntConst("ten", 10),
            bind("absA", new Call("abs", List.of("a"))),
            bind("maxBC", new Call("max", List.of("b", "c"))),
            bind("powBT", new Call("pow", List.of("b", "ten")))
        ));
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(BigInteger.valueOf(7),    bigInt(findBinding(m, "absA").value()));
        assertEquals(BigInteger.valueOf(5),    bigInt(findBinding(m, "maxBC").value()));
        assertEquals(BigInteger.valueOf(1024), bigInt(findBinding(m, "powBT").value()));
    }

    // ---------------------------------------------------------------
    // Side-effect preservation
    // ---------------------------------------------------------------

    @Test
    void doesNotTouchSideEffectingBindings() {
        // assert / update_prop / check_preimage / call to crypto builtin
        // — the folder must leave them as-is even when their inputs are
        // known constants.
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 1),
            bind("t1", new Assert("t0")),
            bind("t2", new UpdateProp("count", "t0")),
            bind("t3", new CheckPreimage("t0")),
            // hash160 is a crypto builtin, not in the pure math list — must NOT fold
            bind("t4", new Call("hash160", List.of("t0")))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "t1").value() instanceof Assert);
        assertTrue(findBinding(m, "t2").value() instanceof UpdateProp);
        assertTrue(findBinding(m, "t3").value() instanceof CheckPreimage);
        AnfValue t4 = findBinding(m, "t4").value();
        assertTrue(t4 instanceof Call, "hash160 must NOT be folded, got " + t4);
        assertEquals("hash160", ((Call) t4).func());
    }

    @Test
    void doesNotFoldWhenInputsAreNotConst() {
        // load_param y, t1 = y + literal 3 — y is unknown so cannot fold.
        List<AnfBinding> body = List.of(
            bind("y", new LoadParam("y")),
            bigIntConst("c", 3),
            bind("t1", new BinOp("+", "y", "c", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertTrue(findBinding(m, "t1").value() instanceof BinOp);
    }

    // ---------------------------------------------------------------
    // CLI plumbing
    // ---------------------------------------------------------------

    @Test
    void disableConstantFoldingFlagSkipsThePass() {
        // The Cli.optimizeAnf helper takes a disable flag and must NOT
        // alter the program when set. AnfOptimize is still allowed to
        // run, but with no constants in the env it cannot do anything
        // that would mutate the bin_op binding.
        //
        // The Assert anchors t2 so the AnfOptimize DCE pass keeps it
        // around — otherwise (with --disable-constant-folding set, the
        // bin_op survives the fold pass but has no consumers and the
        // subsequent dead-binding elimination would remove it).
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 2),
            bigIntConst("t1", 3),
            bind("t2", new BinOp("+", "t0", "t1", null)),
            bind("t3", new Assert("t2"))
        );
        AnfProgram p = singleMethodProgram(body);

        // disabled -> bin_op preserved
        AnfProgram disabled = runar.compiler.Cli.optimizeAnf(p, /* disableConstantFolding */ true);
        AnfBinding t2Disabled = findBinding(soleMethod(disabled), "t2");
        assertTrue(t2Disabled.value() instanceof BinOp,
            "with --disable-constant-folding the bin_op must remain, got "
                + t2Disabled.value().getClass().getSimpleName());

        // enabled -> bin_op folded to load_const(5)
        AnfProgram enabled = runar.compiler.Cli.optimizeAnf(p, /* disableConstantFolding */ false);
        AnfBinding t2Enabled = findBinding(soleMethod(enabled), "t2");
        assertTrue(t2Enabled.value() instanceof LoadConst,
            "with folding enabled the bin_op must fold to load_const, got "
                + t2Enabled.value().getClass().getSimpleName());
        assertEquals(BigInteger.valueOf(5), bigInt(t2Enabled.value()));
    }

    // ---------------------------------------------------------------
    // If-branch folding
    // ---------------------------------------------------------------
    //
    // A statically-known condition must NOT blank the untaken arm.
    //
    // The folder used to return an empty arm while leaving the `if` node itself in
    // place. An arm is not a free-floating binding list — it carries the stack-shape
    // contract AnfLower builds (the __merge$<i> result block for K>=2 merged locals)
    // and StackLower consumes. Erasing one arm made lowerIf register ONE stack slot
    // for K physical results, which at K=2 silently miscompiled the guard (the
    // deployed script accepted spends the source rejects) and at K=1 rejected source
    // that compiles with folding disabled.

    @Test
    void keepsBothArmsWhenConditionKnownTrue() {
        List<AnfBinding> body = List.of(
            boolConst("t0", true),
            bind("t1", new If("t0",
                List.of(bigIntConst("t2", 42)),
                List.of(bigIntConst("t3", 99))))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        AnfValue v = findBinding(m, "t1").value();
        assertTrue(v instanceof If, "expected the if to survive, got " + v.getClass().getSimpleName());
        If ifv = (If) v;
        assertEquals(1, ifv.thenBranch().size());
        assertEquals(1, ifv.elseBranch().size());
    }

    @Test
    void keepsBothArmsWhenConditionKnownFalse() {
        List<AnfBinding> body = List.of(
            boolConst("t0", false),
            bind("t1", new If("t0",
                List.of(bigIntConst("t2", 42)),
                List.of(bigIntConst("t3", 99))))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        AnfValue v = findBinding(m, "t1").value();
        assertTrue(v instanceof If, "expected the if to survive, got " + v.getClass().getSimpleName());
        If ifv = (If) v;
        assertEquals(1, ifv.thenBranch().size());
        assertEquals(1, ifv.elseBranch().size());
    }

    @Test
    void foldsConstantsInsideBothArms() {
        List<AnfBinding> body = List.of(
            bind("t0", new LoadParam("flag")),
            bigIntConst("c1", 5),
            bigIntConst("c2", 3),
            bind("t1", new If("t0",
                List.of(bind("t2", new BinOp("+", "c1", "c2", null))),
                List.of(bind("t3", new BinOp("-", "c1", "c2", null)))))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        If ifv = (If) findBinding(m, "t1").value();
        assertEquals(BigInteger.valueOf(8), bigInt(ifv.thenBranch().get(0).value()));
        assertEquals(BigInteger.valueOf(2), bigInt(ifv.elseBranch().get(0).value()));
    }

    // A statically-known condition must not leak an arm's constants into the
    // enclosing environment either: the `if` survives the pass, so both arms are
    // still emitted and either can run.
    @Test
    void doesNotPropagateTakenArmConstants() {
        List<AnfBinding> body = List.of(
            boolConst("t0", true),
            bind("t1", new If("t0",
                List.of(bigIntConst("x", 42)),
                List.of(bigIntConst("x", 99)))),
            bind("t2", new BinOp("+", "x", "x", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        AnfValue v = findBinding(m, "t2").value();
        assertTrue(v instanceof BinOp,
            "the post-if bin_op must survive unfolded, got " + v.getClass().getSimpleName());
    }

    // ---------------------------------------------------------------
    // Same-name rebinding (F-082)
    // ---------------------------------------------------------------
    //
    // ANF allows a name to be bound more than once in a method body (AnfLower's
    // emitNamed reassignment idiom; a user local whose name collides with a
    // compiler temp). The env entry must track the LATEST binding: when a name
    // is rebound to a non-constant value, the old constant must be dropped, or
    // every later use folds with a value the name no longer holds.
    //
    // Proves: the pass drops a stale constant on rebinding to a load_param and to
    // an `@ref:` alias, and the source-reachable form of the bug (a user local
    // named like an earlier compiler temp) compiles the same bytes with folding
    // ON as with folding OFF — i.e. folding no longer turns an unsatisfiable
    // guard into an unconditional `OP_TRUE`.
    // Does not prove: anything about the other six tiers (they carry the same
    // defect and are fixed separately), nor on-chain acceptance (see the item
    // log for the Spend-based probe).

    @Test
    void rebindingToParamDropsStaleConstant() {
        List<AnfBinding> body = List.of(
            bigIntConst("x", 1),
            bind("x", new LoadParam("p")),
            bigIntConst("c", 1),
            bind("y", new BinOp("+", "x", "c", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        AnfValue y = m.body().get(3).value();
        assertTrue(y instanceof BinOp,
            "y = x + 1 after x was rebound to load_param must stay a bin_op, got " + y);
    }

    @Test
    void rebindingToRefAliasDropsStaleConstant() {
        List<AnfBinding> body = List.of(
            bigIntConst("x", 1),
            bind("t0", new LoadParam("p")),
            bytesConst("x", "@ref:t0"),
            bigIntConst("c", 1),
            bind("y", new BinOp("+", "x", "c", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        AnfValue y = m.body().get(4).value();
        assertTrue(y instanceof BinOp,
            "y = x + 1 after x was rebound to an @ref alias must stay a bin_op, got " + y);
    }

    @Test
    void userLocalCollidingWithTempDoesNotFoldStaleConstant() throws Exception {
        // `0n` in the first assert lowers to temp t1 = 0; `let t1 = p` then
        // rebinds t1 to @ref:<load_param p>. Source semantics: p > 0 && p + 1 == 1
        // is unsatisfiable. Pre-fix, folding used the stale t1 = 0, folded the
        // second assert to assert(true), and the script accepted every p > 0.
        String src = String.join("\n",
            "import { SmartContract, assert } from 'runar-lang';",
            "",
            "class C extends SmartContract {",
            "  constructor() {",
            "    super();",
            "  }",
            "",
            "  public unlock(p: bigint) {",
            "    assert(p > 0n);",
            "    let t1: bigint = p;",
            "    assert(t1 + 1n === 1n);",
            "  }",
            "}",
            "");
        String foldOff = PipelineTestSupport.hex(src, "C.runar.ts", true);
        String foldOn = PipelineTestSupport.hex(src, "C.runar.ts", false);
        // fold-OFF bytes, identical across all 7 tiers.
        assertEquals("76007c78a0697c8b519c77", foldOff);
        assertEquals(foldOff, foldOn,
            "constant folding must not change this program's bytes (stale-constant fold)");
    }

}
