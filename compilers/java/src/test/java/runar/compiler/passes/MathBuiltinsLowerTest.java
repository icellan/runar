package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;

/**
 * Lowering tests for the 8 math builtins {@code clamp}, {@code pow},
 * {@code mulDiv}, {@code sqrt}, {@code gcd}, {@code divmod}, {@code log2},
 * {@code sign}. Each is a direct port of the Go reference at
 * {@code compilers/go/codegen/stack.go} (lines ~3312-3730), so the assertions
 * here check the exact opcode shape (counts of conditional rounds, verbatim
 * opcode codes, structural ops) the Go compiler emits. A divergence between
 * Java and Go would surface as a conformance-runner mismatch but these unit
 * tests catch it directly without rebuilding the cross-compiler harness.
 */
class MathBuiltinsLowerTest {

    private static StackProgram compile(String src, String file) {
        ContractNode contract = JavaParser.parse(src, file);
        Validate.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        return StackLower.run(anf);
    }

    private static StackMethod findMethod(StackProgram p, String name) {
        for (StackMethod m : p.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new IllegalArgumentException("method not found: " + name);
    }

    /**
     * Build a stateless contract that calls a single math builtin and
     * asserts the result equals zero (so the builtin call is reachable
     * but the test doesn't need to know the runtime value). Returns the
     * top-level (non-nested) ops emitted for the public method.
     */
    private static List<StackOp> compileSingleCall(String body) {
        String src = """
            package fixture;

            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;

            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.abs;
            import static runar.lang.Builtins.clamp;
            import static runar.lang.Builtins.pow;
            import static runar.lang.Builtins.mulDiv;
            import static runar.lang.Builtins.sqrt;
            import static runar.lang.Builtins.gcd;
            import static runar.lang.Builtins.divmod;
            import static runar.lang.Builtins.log2;
            import static runar.lang.Builtins.sign;

            class M extends SmartContract {
                @Readonly Bigint a;
                @Readonly Bigint b;
                @Readonly Bigint c;
                M(Bigint a, Bigint b, Bigint c) {
                    super(a, b, c);
                    this.a = a;
                    this.b = b;
                    this.c = c;
                }
                @Public
                void m() {
                    %s
                }
            }
            """.formatted(body);
        StackProgram p = compile(src, "M.runar.java");
        return findMethod(p, "m").ops();
    }

    /** Count opcode hits of {@code code} at any depth (including IfOp branches). */
    private static int countOpcode(List<StackOp> ops, String code) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof OpcodeOp o && o.code().equals(code)) n++;
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) n += countOpcode(i.thenBranch(), code);
                if (i.elseBranch() != null) n += countOpcode(i.elseBranch(), code);
            }
        }
        return n;
    }

    /** Count IfOps at any depth (including IfOp branches). */
    private static int countIfOps(List<StackOp> ops) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof IfOp i) {
                n++;
                if (i.thenBranch() != null) n += countIfOps(i.thenBranch());
                if (i.elseBranch() != null) n += countIfOps(i.elseBranch());
            }
        }
        return n;
    }

    /** Count direct (non-recursive) IfOps. */
    private static int countIfOpsTopLevel(List<StackOp> ops) {
        int n = 0;
        for (StackOp op : ops) if (op instanceof IfOp) n++;
        return n;
    }

    /* ================================================================== */
    /* clamp(val, lo, hi) — OP_MAX then OP_MIN                            */
    /* ================================================================== */

    @Test
    void clampEmitsMaxThenMin() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = clamp(this.a, this.b, this.c); assertThat(r >= Bigint.ZERO);"
        );
        // Find the OP_MAX/OP_MIN — both must appear at top level (not in IF).
        int maxOps = countOpcode(ops, "OP_MAX");
        int minOps = countOpcode(ops, "OP_MIN");
        assertTrue(maxOps >= 1, "clamp must emit OP_MAX");
        assertTrue(minOps >= 1, "clamp must emit OP_MIN");
    }

    @Test
    void clampDoesNotEmitMul() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = clamp(this.a, this.b, this.c); assertThat(r >= Bigint.ZERO);"
        );
        // clamp is purely OP_MAX/OP_MIN — no multiplication should appear.
        // (OP_MUL/OP_DIV would show up only if the dispatch fell through to
        //  another builtin or to the unknown-builtin throw.)
        assertEquals(0, countOpcode(ops, "OP_MUL"), "clamp must not multiply");
    }

    /* ================================================================== */
    /* pow(base, exp) — 32 conditional-multiply rounds                     */
    /* ================================================================== */

    @Test
    void powEmits32ConditionalMultiplyRounds() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = pow(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        // Each round emits an IfOp with {OVER, OP_MUL}. Count IfOps at the
        // call site — there's exactly one outer IF per round (32 rounds).
        // Also one initial OP_PICK per round, plus ONE extra OP_PICK for
        // the runtime exp<=32 guard added in issue #34.
        assertEquals(33, countOpcode(ops, "OP_PICK"),
            "pow must emit 33 OP_PICK opcodes (32 loop iterations + 1 guard)");
        assertEquals(32, countOpcode(ops, "OP_GREATERTHAN"),
            "pow must emit exactly 32 OP_GREATERTHAN opcodes");
        assertEquals(32, countOpcode(ops, "OP_MUL"),
            "pow must emit exactly 32 OP_MUL opcodes (one inside each IF branch)");
        assertEquals(1, countOpcode(ops, "OP_LESSTHANOREQUAL"),
            "pow must emit a single OP_LESSTHANOREQUAL guard (issue #34)");
        assertEquals(1, countOpcode(ops, "OP_VERIFY"),
            "pow must emit a single OP_VERIFY guard (issue #34)");
    }

    @Test
    void powEmitsFinalDoubleNip() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = pow(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        // After 32 rounds the result is at TOS with exp+base below; two NIP
        // ops drop them. We can't trivially assert "exactly 2 trailing NIPs"
        // without tracking position, but we can count NIPs at top level.
        long nipCount = ops.stream().filter(op -> op instanceof NipOp).count();
        assertTrue(nipCount >= 2, "pow must emit at least 2 NIP ops to drop exp+base");
    }

    /* ================================================================== */
    /* mulDiv(a, b, c) — OP_MUL then OP_DIV                                */
    /* ================================================================== */

    @Test
    void mulDivEmitsMulThenDiv() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = mulDiv(this.a, this.b, this.c); assertThat(r >= Bigint.ZERO);"
        );
        assertEquals(1, countOpcode(ops, "OP_MUL"),
            "mulDiv must emit exactly 1 OP_MUL");
        assertEquals(1, countOpcode(ops, "OP_DIV"),
            "mulDiv must emit exactly 1 OP_DIV");
    }

    /* ================================================================== */
    /* sqrt(n) — IF { 16 Newton iterations + nip }                         */
    /* ================================================================== */

    @Test
    void sqrtEmits16NewtonIterations() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = sqrt(this.a); assertThat(r >= Bigint.ZERO);"
        );
        // Each Newton iteration emits: OVER OVER OP_DIV OP_ADD push2 OP_DIV.
        // The 0-guard is wrapped in an IF; the iterations live INSIDE that IF.
        // At 16 iterations: 32 OP_DIV (2 per iter), 16 OP_ADD.
        assertEquals(32, countOpcode(ops, "OP_DIV"),
            "sqrt must emit 32 OP_DIV (2 per Newton iteration × 16)");
        assertEquals(16, countOpcode(ops, "OP_ADD"),
            "sqrt must emit 16 OP_ADD (1 per Newton iteration)");
        // OVER appears 32 times (2 per iter).
        long overCount = ops.stream().filter(op -> op instanceof OverOp).count();
        // At top level: 0 OVERs (they're inside the IF). Recurse.
        long deepOver = deepCountOver(ops);
        assertEquals(32, deepOver, "sqrt must emit 32 OVER ops (2 per iteration × 16)");
    }

    private static long deepCountOver(List<StackOp> ops) {
        long n = 0;
        for (StackOp op : ops) {
            if (op instanceof OverOp) n++;
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) n += deepCountOver(i.thenBranch());
                if (i.elseBranch() != null) n += deepCountOver(i.elseBranch());
            }
        }
        return n;
    }

    @Test
    void sqrtEmitsZeroGuardIf() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = sqrt(this.a); assertThat(r >= Bigint.ZERO);"
        );
        // The Newton iteration is wrapped in a single OP_IF guard at the
        // top level for the call site. There's one DUP before the IF.
        assertTrue(countIfOpsTopLevel(ops) >= 1, "sqrt must wrap iterations in IF");
    }

    /* ================================================================== */
    /* gcd(a, b) — 256 iterations + final OP_DROP                          */
    /* ================================================================== */

    @Test
    void gcdEmits256IterationsAndFinalDrop() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = gcd(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        // Per iteration: OP_DUP OP_0NOTEQUAL IF { OP_TUCK OP_MOD }.
        // 256 iterations × 1 OP_TUCK each (inside IF) + 0 OP_TUCK at top.
        assertEquals(256, countOpcode(ops, "OP_TUCK"),
            "gcd must emit 256 OP_TUCK (one per iteration, inside IF)");
        assertEquals(256, countOpcode(ops, "OP_MOD"),
            "gcd must emit 256 OP_MOD (one per iteration)");
        // OP_DUP + OP_0NOTEQUAL pairs: 256 each at top level
        assertEquals(256, countOpcode(ops, "OP_0NOTEQUAL"),
            "gcd must emit 256 OP_0NOTEQUAL (one per iteration)");
        // Both operands are abs'd up front: 2 OP_ABS at top level.
        assertEquals(2, countOpcode(ops, "OP_ABS"),
            "gcd must emit exactly 2 OP_ABS (one per operand)");
        // Trailing drop.
        long dropCount = ops.stream().filter(op -> op instanceof DropOp).count();
        assertTrue(dropCount >= 1, "gcd must emit a final DROP for the trailing zero");
    }

    /* ================================================================== */
    /* divmod(a, b) — OP_2DUP, OP_DIV, ROT, ROT, OP_MOD, drop              */
    /* ================================================================== */

    @Test
    void divmodEmitsExactOpSequence() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = divmod(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        assertEquals(1, countOpcode(ops, "OP_2DUP"),
            "divmod must emit exactly 1 OP_2DUP");
        assertEquals(1, countOpcode(ops, "OP_DIV"),
            "divmod must emit exactly 1 OP_DIV");
        assertEquals(2, countOpcode(ops, "OP_ROT"),
            "divmod must emit exactly 2 OP_ROT");
        assertEquals(1, countOpcode(ops, "OP_MOD"),
            "divmod must emit exactly 1 OP_MOD");
    }

    @Test
    void divmodOrderingMatchesGoReference() {
        // Walk the call site and confirm: 2DUP -> DIV -> ROT -> ROT -> MOD -> DROP
        List<StackOp> ops = compileSingleCall(
            "Bigint r = divmod(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        // Find the index of OP_2DUP and check the next 5 opcodes.
        int idx2dup = -1;
        for (int i = 0; i < ops.size(); i++) {
            if (ops.get(i) instanceof OpcodeOp o && "OP_2DUP".equals(o.code())) {
                idx2dup = i;
                break;
            }
        }
        assertTrue(idx2dup >= 0, "Expected OP_2DUP somewhere in the op stream");
        List<String> expected = List.of("OP_DIV", "OP_ROT", "OP_ROT", "OP_MOD");
        for (int k = 0; k < expected.size(); k++) {
            StackOp op = ops.get(idx2dup + 1 + k);
            assertTrue(op instanceof OpcodeOp,
                "Expected opcode at offset " + (k + 1) + " after OP_2DUP, got " + op);
            assertEquals(expected.get(k), ((OpcodeOp) op).code(),
                "divmod opcode sequence diverges from Go reference at offset " + (k + 1));
        }
        // Followed by a DropOp to drop the remainder.
        assertTrue(ops.get(idx2dup + 5) instanceof DropOp,
            "divmod must end with a DROP to discard the remainder");
    }

    /* ================================================================== */
    /* log2(n) — 64 iterations + final OP_NIP                              */
    /* ================================================================== */

    @Test
    void log2Emits64Iterations() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = log2(this.a); assertThat(r >= Bigint.ZERO);"
        );
        // Each iteration: swap OP_DUP push1 OP_GREATERTHAN IF{push2 OP_DIV swap OP_1ADD swap} swap
        // 64 OP_DUP at top level (one per iter)
        // 64 OP_GREATERTHAN at top level
        // 64 OP_DIV inside IFs
        // 64 OP_1ADD inside IFs
        assertEquals(64, countOpcode(ops, "OP_DUP"),
            "log2 must emit 64 OP_DUP at iterations");
        assertEquals(64, countOpcode(ops, "OP_GREATERTHAN"),
            "log2 must emit 64 OP_GREATERTHAN");
        assertEquals(64, countOpcode(ops, "OP_DIV"),
            "log2 must emit 64 OP_DIV (one inside each IF body)");
        assertEquals(64, countOpcode(ops, "OP_1ADD"),
            "log2 must emit 64 OP_1ADD (one inside each IF body)");
        // Trailing OP_NIP to drop the input.
        long nipCount = ops.stream().filter(op -> op instanceof NipOp).count();
        assertTrue(nipCount >= 1, "log2 must end with at least one NIP");
        // 64 IF blocks at top level
        assertEquals(64, countIfOpsTopLevel(ops),
            "log2 must emit exactly 64 top-level IF blocks");
    }

    /* ================================================================== */
    /* sign(x) — OP_DUP IF { OP_DUP OP_ABS swap OP_DIV }                    */
    /* ================================================================== */

    @Test
    void signEmitsZeroGuardedDivision() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = sign(this.a); assertThat(r >= Bigint.ZERO);"
        );
        // Outer OP_DUP, then IF with body { OP_DUP, OP_ABS, swap, OP_DIV }
        assertEquals(1, countIfOpsTopLevel(ops),
            "sign must emit exactly 1 top-level IF guard");
        // Recursively count: 2 OP_DUP (one outer, one in IF), 1 OP_ABS, 1 OP_DIV
        assertEquals(2, countOpcode(ops, "OP_DUP"),
            "sign must emit 2 OP_DUP (outer + inside IF)");
        assertEquals(1, countOpcode(ops, "OP_ABS"),
            "sign must emit 1 OP_ABS inside the IF");
        assertEquals(1, countOpcode(ops, "OP_DIV"),
            "sign must emit 1 OP_DIV inside the IF");
    }

    @Test
    void signIfBodyContainsExactSequence() {
        List<StackOp> ops = compileSingleCall(
            "Bigint r = sign(this.a); assertThat(r >= Bigint.ZERO);"
        );
        // Locate the IF and inspect its body.
        IfOp ifOp = null;
        for (StackOp op : ops) {
            if (op instanceof IfOp i) {
                ifOp = i;
                break;
            }
        }
        assertNotNull(ifOp, "Expected an IF op for the sign zero-guard");
        List<StackOp> body = ifOp.thenBranch();
        assertNotNull(body);
        assertEquals(4, body.size(), "sign IF body has 4 ops");
        assertTrue(body.get(0) instanceof OpcodeOp o1 && "OP_DUP".equals(o1.code()));
        assertTrue(body.get(1) instanceof OpcodeOp o2 && "OP_ABS".equals(o2.code()));
        assertTrue(body.get(2) instanceof SwapOp);
        assertTrue(body.get(3) instanceof OpcodeOp o4 && "OP_DIV".equals(o4.code()));
    }

    /* ================================================================== */
    /* Negative path: passing wrong arity to a math builtin is rejected at  */
    /* typecheck (BuiltinRegistry). The lowerer is never reached for these. */
    /* ================================================================== */

    @Test
    void wrongArityRejectedBeforeLowering() {
        // clamp wants 3 args; pass only 2.
        String src = """
            package fixture;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.clamp;
            class M extends SmartContract {
                @Readonly Bigint a;
                M(Bigint a) {
                    super(a);
                    this.a = a;
                }
                @Public
                void m() {
                    Bigint r = clamp(this.a, this.a);
                    assertThat(r >= Bigint.ZERO);
                }
            }
            """;
        // Either parse, validate, or typecheck must reject before reaching lowerClamp.
        assertThrows(Exception.class, () -> compile(src, "M.runar.java"),
            "Expected an arity rejection before reaching the lowerer");
    }

    @Test
    void allEightBuiltinsCompose() {
        // Build a single method that calls all 8 builtins in a chain;
        // proves the dispatch table doesn't mistakenly fall through to
        // the "unknown builtin" throw for any of them.
        String body = """
            Bigint x = pow(this.a, this.b);
            Bigint y = mulDiv(x, this.b, this.c);
            Bigint z = clamp(y, this.a, this.c);
            Bigint w = sqrt(z);
            Bigint v = gcd(w, this.b);
            Bigint u = divmod(v, this.b);
            Bigint t = log2(u);
            Bigint s = sign(t);
            assertThat(s >= Bigint.ZERO);
            """;
        // Should not throw.
        List<StackOp> ops = compileSingleCall(body);
        assertNotNull(ops);
        assertTrue(ops.size() > 0);
    }

    /* ================================================================== */
    /* Constants matching the Go reference                                  */
    /* ================================================================== */

    @Test
    void powIterationsMatchGoReference32() {
        // Go's lowerPow at compilers/go/codegen/stack.go:3470 uses
        // const maxPowIterations = 32. Java MUST match.
        List<StackOp> ops = compileSingleCall(
            "Bigint r = pow(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        assertEquals(32, countIfOpsTopLevel(ops),
            "Java pow must emit exactly 32 top-level IF rounds (Go reference)");
    }

    @Test
    void sqrtIterationsMatchGoReference16() {
        // Go's lowerSqrt at stack.go:3576 uses const sqrtIterations = 16.
        List<StackOp> ops = compileSingleCall(
            "Bigint r = sqrt(this.a); assertThat(r >= Bigint.ZERO);"
        );
        // 16 iterations × OP_ADD = 16
        assertEquals(16, countOpcode(ops, "OP_ADD"),
            "Java sqrt must emit exactly 16 OP_ADDs (Go reference: 16 iterations)");
    }

    @Test
    void gcdIterationsMatchGoReference256() {
        // Go's lowerGcd at stack.go:3623 uses const gcdIterations = 256.
        List<StackOp> ops = compileSingleCall(
            "Bigint r = gcd(this.a, this.b); assertThat(r >= Bigint.ZERO);"
        );
        // 256 iterations of {OP_DUP OP_0NOTEQUAL IF{OP_TUCK OP_MOD}}
        assertEquals(256, countIfOpsTopLevel(ops),
            "Java gcd must emit exactly 256 top-level IF rounds (Go reference)");
    }

    @Test
    void log2IterationsMatchGoReference64() {
        // Go's lowerLog2 at stack.go:3703 uses const log2Iterations = 64.
        List<StackOp> ops = compileSingleCall(
            "Bigint r = log2(this.a); assertThat(r >= Bigint.ZERO);"
        );
        assertEquals(64, countIfOpsTopLevel(ops),
            "Java log2 must emit exactly 64 top-level IF rounds (Go reference)");
    }
}
