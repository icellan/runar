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
    void foldsBitwiseAndOrXor() {
        // t0=0b1100=12, t1=0b1010=10
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 12),
            bigIntConst("t1", 10),
            bind("a", new BinOp("&", "t0", "t1", null)),  // 0b1000 = 8
            bind("o", new BinOp("|", "t0", "t1", null)),  // 0b1110 = 14
            bind("x", new BinOp("^", "t0", "t1", null))   // 0b0110 = 6
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(BigInteger.valueOf(8),  bigInt(findBinding(m, "a").value()));
        assertEquals(BigInteger.valueOf(14), bigInt(findBinding(m, "o").value()));
        assertEquals(BigInteger.valueOf(6),  bigInt(findBinding(m, "x").value()));
    }

    @Test
    void foldsShiftsAndBitNot() {
        // t0=5, t1=2, shl=20, shr=1, neg=~5=-6
        List<AnfBinding> body = List.of(
            bigIntConst("t0", 5),
            bigIntConst("t1", 2),
            bind("shl", new BinOp("<<", "t0", "t1", null)),
            bind("shr", new BinOp(">>", "t0", "t1", null)),
            bind("neg", new UnaryOp("~", "t0", null))
        );
        AnfMethod m = soleMethod(ConstantFold.run(singleMethodProgram(body)));
        assertEquals(BigInteger.valueOf(20), bigInt(findBinding(m, "shl").value()));
        assertEquals(BigInteger.valueOf(1),  bigInt(findBinding(m, "shr").value()));
        assertEquals(BigInteger.valueOf(-6), bigInt(findBinding(m, "neg").value()));
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
}
