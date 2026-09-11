package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

/**
 * R-065 regression guard for the Java tier: the for-loop {@code update} clause is parsed,
 * carried through the whole AST, and then never validated and never lowered.
 *
 * <p>{@code AnfLower}'s {@code extractLoopStep} only ever understood a UNIT step: it returns
 * {@code 1} for {@code IncrementExpr}, {@code -1} for {@code DecrementExpr}, and otherwise falls
 * back to the <em>comparison direction</em> — so any other update clause is silently coerced to
 * {@code ±1} and the clause itself is discarded. {@code Validate.validateForStatement} never
 * looked at {@code f.update()} at all, and {@code Typecheck}'s {@code ForStatement} arm checked
 * {@code init}, {@code condition} and {@code body} but skipped {@code update} entirely.
 *
 * <p>Three shapes of the same hole, all observable from ordinary source:
 *
 * <ul>
 *   <li>{@code for (let i = 0n; i < 3n; undefinedFn())} compiled to byte-identical output. A
 *       nonexistent function name raised nothing — a hole in the rule that only Rúnar builtins and
 *       contract methods are callable (CLAUDE.md names {@code console.log} explicitly).
 *   <li>{@code for (let i = 0n; i < 3n; this.count++)} silently DROPPED the state write from the
 *       emitted script.
 *   <li>a non-unit step ({@code i += 2} in the Go / Zig / Solidity surface formats) unrolled 5
 *       times over i = 0..4 instead of 3 times over i = 0,2,4 — byte-identical to the {@code i++}
 *       loop, with no diagnostic.
 * </ul>
 *
 * <p>{@code spec/grammar.md} is authoritative and permits only the unit forms: its ForStatement
 * production admits {@code Identifier ( '++' | '--' )} and nothing else, and its Statement
 * Restrictions say "The loop variable MUST use simple increment ({@code ++}) or decrement
 * ({@code --})". So rejecting is the fix rather than lowering: the ANF {@code loop} node can
 * express exactly {@code {count, iterVar, start, step, body}} and synthesizes the iterator on
 * unrolled iteration k as {@code start + k*step}. There is no slot for an arbitrary update
 * statement, and appending the update's lowering to the loop body would re-emit {@code i++} as a
 * dead binding on every loop that already compiles correctly — moving bytes across the whole
 * corpus to express nothing.
 *
 * <p>The diagnostic text is shared verbatim with the other six tiers.
 *
 * <p>What these tests do NOT prove: nothing here says the update clause is <em>lowered</em>; the
 * contract is that a non-representable update is a compile error instead of silent output. The
 * controls pin the {@code bounded-loop} shape only.
 */
class LoopUpdateClauseTest {

    /**
     * The one correct answer. {@code bounded-loop} sums {@code start + i} for i in 0..4 and asserts
     * the total; all nine frontends lower to these exact 42 bytes.
     */
    private static final String BOUNDED_LOOP_HEX =
        "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c";

    private static final String LOOP_UPDATE_DIAGNOSTIC = "must advance the loop variable by one";

    private static final Path REPO_ROOT = Paths.get("").toAbsolutePath().resolve("../..").normalize();

    private static String example(String rel) throws Exception {
        return Files.readString(REPO_ROOT.resolve(rel));
    }

    /** A stateful contract parameterised on the for-loop update clause. */
    private static String tsWithUpdate(String update) {
        return """
            import { StatefulSmartContract, assert } from 'runar-lang';

            class UpdateProbe extends StatefulSmartContract {
              count: bigint;

              constructor(count: bigint) { super(count); this.count = count; }

              public unlock(expected: bigint): void {
                let acc: bigint = 0n;
                for (let i: bigint = 0n; i < 3n; UPDATE) {
                  acc = acc + i;
                }
                assert(acc === expected);
              }
            }"""
            .replace("UPDATE", update);
    }

    /** Compile and return the failure message, or null when the compile succeeded. */
    private static String compileError(String src, String file) {
        try {
            PipelineTestSupport.hex(src, file);
            return null;
        } catch (Exception e) {
            String msg = e.getMessage();
            return msg == null ? e.toString() : msg;
        }
    }

    private static void assertRejectedWithSharedDiagnostic(String src, String file, String why) {
        String err = compileError(src, file);
        if (err == null) {
            fail(why);
        }
        assertTrue(err.contains(LOOP_UPDATE_DIAGNOSTIC),
            "rejection must carry the shared cross-tier diagnostic, got: " + err);
    }

    // -----------------------------------------------------------------------
    // The defect
    // -----------------------------------------------------------------------

    /** The Zig {@code while (c) : (i += 2)} fold produces the ASSIGNMENT spelling {@code i = i + 2}. */
    @Test
    void nonUnitStepIsRejectedNotCoercedZig() throws Exception {
        String src = example("examples/zig/bounded-loop/BoundedLoop.runar.zig")
            .replaceFirst("i \\+= 1", "i += 2");
        assertRejectedWithSharedDiagnostic(src, "BoundedLoop.runar.zig",
            "`i += 2` must not compile: it silently unrolled with step 1");
    }

    /** The Go surface spelling of the same thing. */
    @Test
    void nonUnitStepIsRejectedNotCoercedGo() throws Exception {
        String src = example("examples/go/bounded-loop/BoundedLoop.runar.go")
            .replaceFirst("i\\+\\+", "i += 2");
        assertRejectedWithSharedDiagnostic(src, "BoundedLoop.runar.go",
            "`i += 2` must not compile through the Go frontend");
    }

    /** Guards against an accepted set that only checks counting up. */
    @Test
    void negativeNonUnitStepIsRejected() throws Exception {
        String src = example("examples/zig/bounded-loop/BoundedLoop.runar.zig")
            .replaceFirst("var i: i64 = 0;", "var i: i64 = 5;")
            .replaceFirst("while \\(i < 5\\) : \\(i \\+= 1\\)", "while (i > 0) : (i -= 2)");
        assertRejectedWithSharedDiagnostic(src, "BoundedLoop.runar.zig",
            "`i -= 2` must not compile");
    }

    /**
     * The silent-drop half. {@code this.count++} in the update position is a write to contract
     * state that never reached the emitted script.
     */
    @Test
    void stateMutationInUpdateIsRejectedNotDropped() {
        assertRejectedWithSharedDiagnostic(tsWithUpdate("this.count++"), "UpdateProbe.runar.ts",
            "a state mutation in the update clause is not representable in the ANF loop node, "
                + "so it must be a compile error — silently dropping it is what this test forbids");
    }

    @Test
    void updateAdvancingAnotherVariableIsRejected() {
        String src = """
            import { SmartContract, assert } from 'runar-lang';

            class OtherVar extends SmartContract {
              readonly expected: bigint;

              constructor(expected: bigint) { super(expected); this.expected = expected; }

              public verify(start: bigint): void {
                let sum: bigint = 0n;
                let j: bigint = 0n;
                for (let i: bigint = 0n; i < 3n; j++) {
                  sum = sum + start + i;
                }
                assert(sum === this.expected);
              }
            }""";
        assertRejectedWithSharedDiagnostic(src, "OtherVar.runar.ts",
            "`j++` advances a variable the loop model never binds");
    }

    /** The rejection must be a diagnostic, not a crash with an empty message. */
    @Test
    void rejectionIsADiagnosticNotACrash() {
        String err = compileError(tsWithUpdate("this.count++"), "UpdateProbe.runar.ts");
        assertFalse(err == null || err.isBlank(),
            "rejection must carry a diagnostic, got an empty message");
    }

    // -----------------------------------------------------------------------
    // Controls: every shape that compiles today must still compile, byte-identical
    // -----------------------------------------------------------------------

    @Test
    void controlBoundedLoopBytesUnchanged() throws Exception {
        String[][] controls = {
            {"examples/ts/bounded-loop/BoundedLoop.runar.ts", "BoundedLoop.runar.ts"},
            {"examples/sol/bounded-loop/BoundedLoop.runar.sol", "BoundedLoop.runar.sol"},
            {"examples/go/bounded-loop/BoundedLoop.runar.go", "BoundedLoop.runar.go"},
            {"examples/move/bounded-loop/BoundedLoop.runar.move", "BoundedLoop.runar.move"},
            {"examples/python/bounded-loop/BoundedLoop.runar.py", "BoundedLoop.runar.py"},
            // `while (i < 5) : (i += 1)` — the assignment spelling `i = i + 1`, which the
            // accepted set has to keep alongside `i++`.
            {"examples/zig/bounded-loop/BoundedLoop.runar.zig", "BoundedLoop.runar.zig"},
            // `i = i.plus(Bigint.ONE)` — the Java surface's unit-step spelling.
            {"examples/java/src/main/java/runar/examples/bounded-loop/BoundedLoop.runar.java",
                "BoundedLoop.runar.java"},
        };
        for (String[] c : controls) {
            assertEquals(BOUNDED_LOOP_HEX, PipelineTestSupport.hex(example(c[0]), c[1]),
                c[1] + ": lowering moved bytes");
        }
    }

    /** {@code i--} with {@code >}: guards against an accepted set that only counts up. */
    @Test
    void controlCountdownStillCompiles() throws Exception {
        String src = """
            import { SmartContract, assert } from 'runar-lang';

            class Countdown extends SmartContract {
              readonly expected: bigint;

              constructor(expected: bigint) { super(expected); this.expected = expected; }

              public verify(start: bigint): void {
                let sum: bigint = 0n;
                for (let i: bigint = 3n; i > 0n; i--) {
                  sum = sum + start + i;
                }
                assert(sum === this.expected);
              }
            }""";
        PipelineTestSupport.hex(src, "Countdown.runar.ts");
    }
}
