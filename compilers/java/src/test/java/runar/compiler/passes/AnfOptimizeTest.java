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
 * <p>Two groups. The first group (identity* / ecAddNegateCancel* through
 * identityIsReferentiallyStable) uses programs with no recognized EC call,
 * so {@link AnfOptimize#run} takes its early-return gate and the pass is
 * an identity transformation for them — these tests pin THAT gate, not the
 * EC rule table. The second group (F-318, below) drives all 13 documented
 * EC algebraic-simplification rules (1-12 plus 8r) with a program that DOES
 * contain a recognized EC call, one rule-level positive case plus a
 * near-miss per rule, so the rule table itself has coverage beyond the
 * gate.
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

    /** Like {@link #findValue} but returns {@code null} instead of throwing. */
    private static AnfValue tryFindValue(AnfProgram p, String name) {
        for (AnfBinding b : bodyOf(p)) {
            if (b.name().equals(name)) return b.value();
        }
        return null;
    }

    @Test
    void identityIsReferentiallyStable() {
        // The pass returns the same program reference when there is nothing
        // to do — callers can rely on identity semantics for caching.
        AnfProgram in = singleMethod("m", List.of(bind("t0", new LoadParam("x"))));
        assertSame(in, AnfOptimize.run(in));
    }

    // ===================================================================
    // F-318: rule-level tests for all 13 documented EC rules (1-12 + 8r).
    //
    // Rule 8 / 8r are already covered above by
    // ecAddNegateCancelFoldsInBothOperandOrders /
    // ecAddOverDistinctPointsDoesNotFold. This section adds the remaining
    // 11 rules, each with a positive case asserting the exact rewrite (ANF
    // shape, including the N-104 operand gate where the rule emits one)
    // and a near-miss case proving the rule does NOT fire on a structurally
    // close input, mirroring packages/runar-compiler/src/__tests__/anf-ec-optimizer.test.ts.
    //
    // What these tests prove: AnfOptimize's EC rule table performs the
    // specific algebraic rewrite each rule claims, on a minimal top-level
    // ANF binding, and leaves a structurally similar non-matching program
    // untouched. What they do NOT prove: cross-tier byte parity (that is
    // conformance's job) or correctness of the underlying secp256k1 math
    // (covered by execution-level tests elsewhere, e.g.
    // n104-ec-optimizer-operand-gate.test.ts).
    // ===================================================================

    private static final String INFINITY_HEX = "0".repeat(128);
    private static final BigInteger GEN_X = new BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GEN_Y = new BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final String G_HEX = pad64(GEN_X) + pad64(GEN_Y);
    private static final BigInteger CURVE_N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private static String pad64(BigInteger v) {
        String hex = v.toString(16);
        return "0".repeat(64 - hex.length()) + hex;
    }

    private static AnfValue aliasTarget(AnfValue v) {
        assertEquals(LoadConst.class, v.getClass(), "must be an alias load_const");
        BytesConst bs = (BytesConst) ((LoadConst) v).value();
        assertEquals(true, bs.hex().startsWith("@ref:"), "must be an @ref: alias, got " + bs.hex());
        return v;
    }

    private static String aliasedName(AnfValue v) {
        aliasTarget(v);
        BytesConst bs = (BytesConst) ((LoadConst) v).value();
        return bs.hex().substring(5);
    }

    // --- Rule 1: ecAdd(x, INFINITY) -> x, with ecAdd's N-104 operand gate ---

    @Test
    void ruleOneEcAddIdentityRightFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("pt")));
        in.add(bind("t1", new LoadConst(new BytesConst(INFINITY_HEX))));
        in.add(bind("t2", new Call("ecAdd", List.of("t0", "t1"))));
        in.add(bind("t3", new Assert("t2")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        assertEquals("t0", aliasedName(findValue(out, "t2")));
        assertEquals(Assert.class, findValue(out, "t2_gate").getClass(),
            "ecAdd's operand gate must be emitted for the surviving operand");
        // Distinguish ecAdd's gate shape (ecPointX/Y + canonicity compares) from
        // ecMul's (on-curve-or-O), so a mutation that swaps one gate for the
        // other is caught, not just "some gate exists".
        AnfValue px = findValue(out, "t2_px");
        assertEquals(Call.class, px.getClass());
        assertEquals("ecPointX", ((Call) px).func());
    }

    // --- Rule 2: ecAdd(INFINITY, x) -> x, with ecAdd's N-104 operand gate ---

    @Test
    void ruleTwoEcAddIdentityLeftFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadConst(new BytesConst(INFINITY_HEX))));
        in.add(bind("t1", new LoadParam("pt")));
        in.add(bind("t2", new Call("ecAdd", List.of("t0", "t1"))));
        in.add(bind("t3", new Assert("t2")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        assertEquals("t1", aliasedName(findValue(out, "t2")));
        assertEquals(Assert.class, findValue(out, "t2_gate").getClass(),
            "ecAdd's operand gate must be emitted for the surviving operand");
        AnfValue px = findValue(out, "t2_px");
        assertEquals(Call.class, px.getClass());
        assertEquals("ecPointX", ((Call) px).func());
    }

    /** Near-miss for Rules 1 and 2: neither operand is infinity, so neither fires. */
    @Test
    void ruleOneAndTwoNearMissNeitherOperandInfinityDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadConst(new BytesConst("ab".repeat(64)))));
        in.add(bind("q", new LoadConst(new BytesConst("cd".repeat(64)))));
        in.add(bind("t2", new Call("ecAdd", List.of("p", "q"))));
        in.add(bind("t3", new Assert("t2")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t2");
        assertEquals(Call.class, v.getClass(), "ecAdd must survive when neither operand is infinity");
        assertEquals("ecAdd", ((Call) v).func());
    }

    // --- Rule 3: ecMul(x, 1) -> x, with ecMul's N-104 operand gate ---

    @Test
    void ruleThreeEcMulOneFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("pt")));
        in.add(bind("t1", new LoadConst(new BigIntConst(BigInteger.ONE))));
        in.add(bind("t2", new Call("ecMul", List.of("t0", "t1"))));
        in.add(bind("t3", new Assert("t2")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        assertEquals("t0", aliasedName(findValue(out, "t2")));
        assertEquals(Assert.class, findValue(out, "t2_gate").getClass(),
            "ecMul's on-curve-or-O operand gate must be emitted");
        // Distinguish ecMul's gate shape (infinity-or-on-curve) from ecAdd's
        // (ecPointX/Y canonicity), so a mutation that swaps one gate for the
        // other is caught, not just "some gate exists".
        AnfValue onCurve = findValue(out, "t2_oncurve");
        assertEquals(Call.class, onCurve.getClass());
        assertEquals("ecOnCurve", ((Call) onCurve).func());
    }

    // --- Rule 4: ecMul(x, 0) -> INFINITY, with ecMul's N-104 operand gate ---

    @Test
    void ruleFourEcMulZeroFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("pt")));
        in.add(bind("t1", new LoadConst(new BigIntConst(BigInteger.ZERO))));
        in.add(bind("t2", new Call("ecMul", List.of("t0", "t1"))));
        in.add(bind("t3", new Assert("t2")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        AnfValue v = findValue(out, "t2");
        assertEquals(LoadConst.class, v.getClass());
        assertEquals(INFINITY_HEX, ((BytesConst) ((LoadConst) v).value()).hex());
        assertEquals(Assert.class, findValue(out, "t2_gate").getClass(),
            "ecMul's on-curve-or-O operand gate must be emitted");
        AnfValue onCurve = findValue(out, "t2_oncurve");
        assertEquals(Call.class, onCurve.getClass());
        assertEquals("ecOnCurve", ((Call) onCurve).func());
    }

    /** Near-miss for Rules 3 and 4: scalar is neither 0 nor 1, so neither fires. */
    @Test
    void ruleThreeAndFourNearMissScalarNeitherZeroNorOneDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("pt")));
        in.add(bind("t1", new LoadConst(new BigIntConst(BigInteger.TWO))));
        in.add(bind("t2", new Call("ecMul", List.of("t0", "t1"))));
        in.add(bind("t3", new Assert("t2")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t2");
        assertEquals(Call.class, v.getClass(), "ecMul must survive for a non-0/1 scalar");
        assertEquals("ecMul", ((Call) v).func());
    }

    // --- Rule 5: ecMulGen(0) -> INFINITY ---

    @Test
    void ruleFiveEcMulGenZeroFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadConst(new BigIntConst(BigInteger.ZERO))));
        in.add(bind("t1", new Call("ecMulGen", List.of("t0"))));
        in.add(bind("t2", new Assert("t1")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t1");
        assertEquals(LoadConst.class, v.getClass());
        assertEquals(INFINITY_HEX, ((BytesConst) ((LoadConst) v).value()).hex());
    }

    // --- Rule 6: ecMulGen(1) -> G ---

    @Test
    void ruleSixEcMulGenOneFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadConst(new BigIntConst(BigInteger.ONE))));
        in.add(bind("t1", new Call("ecMulGen", List.of("t0"))));
        in.add(bind("t2", new Assert("t1")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t1");
        assertEquals(LoadConst.class, v.getClass());
        assertEquals(G_HEX, ((BytesConst) ((LoadConst) v).value()).hex());
    }

    /** Near-miss for Rules 5 and 6: scalar is neither 0 nor 1, so neither fires. */
    @Test
    void ruleFiveAndSixNearMissScalarNeitherZeroNorOneDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadConst(new BigIntConst(BigInteger.TWO))));
        in.add(bind("t1", new Call("ecMulGen", List.of("t0"))));
        in.add(bind("t2", new Assert("t1")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t1");
        assertEquals(Call.class, v.getClass(), "ecMulGen must survive for a non-0/1 scalar");
        assertEquals("ecMulGen", ((Call) v).func());
    }

    // --- Rule 7: ecNegate(ecNegate(x)) -> x ---

    @Test
    void ruleSevenEcNegateNegateFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("pt")));
        in.add(bind("t1", new Call("ecNegate", List.of("t0"))));
        in.add(bind("t2", new Call("ecNegate", List.of("t1"))));
        in.add(bind("t3", new Assert("t2")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        assertEquals("t0", aliasedName(findValue(out, "t2")));
    }

    /** Near-miss for Rule 7: a single negation must not fold away. */
    @Test
    void ruleSevenNearMissSingleNegateDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadParam("pt")));
        in.add(bind("t1", new Call("ecNegate", List.of("t0"))));
        in.add(bind("t2", new Assert("t1")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t1");
        assertEquals(Call.class, v.getClass(), "a single ecNegate must survive");
        assertEquals("ecNegate", ((Call) v).func());
    }

    // --- Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, (k1*k2) mod N) ---

    @Test
    void ruleNineEcMulAssociativeFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadParam("pt")));
        in.add(bind("k1", new LoadConst(new BigIntConst(BigInteger.valueOf(3)))));
        in.add(bind("inner", new Call("ecMul", List.of("p", "k1"))));
        in.add(bind("k2", new LoadConst(new BigIntConst(BigInteger.valueOf(4)))));
        in.add(bind("outer", new Call("ecMul", List.of("inner", "k2"))));
        in.add(bind("t3", new Assert("outer")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        AnfValue v = findValue(out, "outer");
        assertEquals(Call.class, v.getClass());
        Call c = (Call) v;
        assertEquals("ecMul", c.func());
        assertEquals("p", c.args().get(0), "the fused call must multiply the ORIGINAL point, not the inner ecMul");
        AnfValue scalar = findValue(out, c.args().get(1));
        assertEquals(LoadConst.class, scalar.getClass());
        assertEquals(BigInteger.valueOf(12), ((BigIntConst) ((LoadConst) scalar).value()).value(),
            "fused scalar must be (3*4) mod N = 12");
    }

    /** Near-miss for Rule 9: the inner scalar is not a compile-time constant, so it cannot fuse. */
    @Test
    void ruleNineNearMissNonConstInnerScalarDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadParam("pt")));
        in.add(bind("k1", new LoadParam("k1"))); // not a constant
        in.add(bind("inner", new Call("ecMul", List.of("p", "k1"))));
        in.add(bind("k2", new LoadConst(new BigIntConst(BigInteger.valueOf(4)))));
        in.add(bind("outer", new Call("ecMul", List.of("inner", "k2"))));
        in.add(bind("t3", new Assert("outer")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "outer");
        assertEquals(Call.class, v.getClass());
        assertEquals("ecMul", ((Call) v).func());
        assertEquals("inner", ((Call) v).args().get(0), "must still multiply the unfused inner ecMul");
    }

    // --- Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen((k1+k2) mod N) ---

    @Test
    void ruleTenEcMulGenLinearFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadConst(new BigIntConst(BigInteger.valueOf(5)))));
        in.add(bind("t1", new Call("ecMulGen", List.of("t0"))));
        in.add(bind("t2", new LoadConst(new BigIntConst(BigInteger.valueOf(7)))));
        in.add(bind("t3", new Call("ecMulGen", List.of("t2"))));
        in.add(bind("t4", new Call("ecAdd", List.of("t1", "t3"))));
        in.add(bind("t5", new Assert("t4")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        AnfValue v = findValue(out, "t4");
        assertEquals(Call.class, v.getClass());
        Call c = (Call) v;
        assertEquals("ecMulGen", c.func());
        AnfValue scalar = findValue(out, c.args().get(0));
        assertEquals(LoadConst.class, scalar.getClass());
        assertEquals(BigInteger.valueOf(12), ((BigIntConst) ((LoadConst) scalar).value()).value(),
            "combined scalar must be (5+7) mod N = 12");
    }

    /** Near-miss for Rule 10: one operand is not an ecMulGen call, so it cannot combine. */
    @Test
    void ruleTenNearMissNonMulGenOperandDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("t0", new LoadConst(new BigIntConst(BigInteger.valueOf(5)))));
        in.add(bind("t1", new Call("ecMulGen", List.of("t0"))));
        in.add(bind("t2", new LoadParam("pt"))); // not an ecMulGen call
        in.add(bind("t4", new Call("ecAdd", List.of("t1", "t2"))));
        in.add(bind("t5", new Assert("t4")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t4");
        assertEquals(Call.class, v.getClass());
        assertEquals("ecAdd", ((Call) v).func(), "ecAdd must survive when one operand is not ecMulGen");
    }

    // --- Rule 11: ecAdd(ecMul(p,k1), ecMul(p,k2)) -> ecMul(p, (k1+k2) mod N) ---

    @Test
    void ruleElevenEcMulDistributiveFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadParam("pt")));
        in.add(bind("k1", new LoadConst(new BigIntConst(BigInteger.valueOf(3)))));
        in.add(bind("left", new Call("ecMul", List.of("p", "k1"))));
        in.add(bind("k2", new LoadConst(new BigIntConst(BigInteger.valueOf(9)))));
        in.add(bind("right", new Call("ecMul", List.of("p", "k2"))));
        in.add(bind("t4", new Call("ecAdd", List.of("left", "right"))));
        in.add(bind("t5", new Assert("t4")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        AnfValue v = findValue(out, "t4");
        assertEquals(Call.class, v.getClass());
        Call c = (Call) v;
        assertEquals("ecMul", c.func());
        assertEquals("p", c.args().get(0), "must multiply the shared point");
        AnfValue scalar = findValue(out, c.args().get(1));
        assertEquals(LoadConst.class, scalar.getClass());
        assertEquals(BigInteger.valueOf(12), ((BigIntConst) ((LoadConst) scalar).value()).value(),
            "combined scalar must be (3+9) mod N = 12");
    }

    /** Near-miss for Rule 11: the two ecMul calls multiply DIFFERENT points, so they cannot combine. */
    @Test
    void ruleElevenNearMissDifferentPointsDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadParam("p")));
        in.add(bind("q", new LoadParam("q"))); // a different point
        in.add(bind("k1", new LoadConst(new BigIntConst(BigInteger.valueOf(3)))));
        in.add(bind("left", new Call("ecMul", List.of("p", "k1"))));
        in.add(bind("k2", new LoadConst(new BigIntConst(BigInteger.valueOf(9)))));
        in.add(bind("right", new Call("ecMul", List.of("q", "k2"))));
        in.add(bind("t4", new Call("ecAdd", List.of("left", "right"))));
        in.add(bind("t5", new Assert("t4")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t4");
        assertEquals(Call.class, v.getClass());
        assertEquals("ecAdd", ((Call) v).func(), "ecAdd must survive when the two ecMul points differ");
    }

    // --- Rule 12: ecMul(G, k) -> ecMulGen(k) ---

    @Test
    void ruleTwelveEcMulGeneratorSpecializeFolds() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("g", new LoadConst(new BytesConst(G_HEX))));
        in.add(bind("k", new LoadParam("k")));
        in.add(bind("t1", new Call("ecMul", List.of("g", "k"))));
        in.add(bind("t2", new Assert("t1")));

        AnfProgram out = AnfOptimize.run(singleMethod("m", in));
        AnfValue v = findValue(out, "t1");
        assertEquals(Call.class, v.getClass());
        Call c = (Call) v;
        assertEquals("ecMulGen", c.func());
        assertEquals("k", c.args().get(0), "the scalar argument must be passed through unchanged");
    }

    /** Near-miss for Rule 12: the point operand is not G, so ecMul must survive. */
    @Test
    void ruleTwelveNearMissNonGeneratorPointDoesNotFold() {
        List<AnfBinding> in = new ArrayList<>();
        in.add(bind("p", new LoadConst(new BytesConst("ab".repeat(64))))); // not G
        in.add(bind("k", new LoadParam("k")));
        in.add(bind("t1", new Call("ecMul", List.of("p", "k"))));
        in.add(bind("t2", new Assert("t1")));

        AnfValue v = findValue(AnfOptimize.run(singleMethod("m", in)), "t1");
        assertEquals(Call.class, v.getClass());
        assertEquals("ecMul", ((Call) v).func(), "ecMul must survive when the point is not G");
    }
}
