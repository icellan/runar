package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.TsParser;
import runar.compiler.ir.ast.ContractNode;

/**
 * H2 (#131): locktime soundness warning.
 *
 * <p>A method that reads {@code extractLocktime(preimage)} only enforces a
 * timelock if the covenant ALSO asserts the spending tx is non-final
 * ({@code extractSequence(preimage) < 0xffffffff}). Without that, a hand-built
 * all-final-sequence transaction bypasses the locktime gate. The compiler emits
 * an advisory WARNING (non-fatal) when a public method reads extractLocktime but
 * does not (transitively) assert a sequence-finality guard.
 *
 * <p>Port of {@code remediation-h2-locktime-sequence-warning.test.ts}. Sources
 * are parsed on the {@code .runar.ts} surface — the guard lives in the shared
 * validator and is format-agnostic.
 */
class H2LocktimeWarningTest {

    private static final String WARNING_NEEDLE = "does not assert extractSequence";

    private static Validate.Result validateSource(String source) throws TsParser.ParseException {
        ContractNode contract = TsParser.parse(source, "TimeLock.runar.ts");
        return Validate.runCollecting(contract);
    }

    private static boolean hasLocktimeWarning(Validate.Result result) {
        return result.warnings().stream().anyMatch(w -> w.contains(WARNING_NEEDLE));
    }

    @Test
    void warnsWhenMethodReadsLocktimeButHasNoSequenceGuard() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              public unlock() {
                assert(extractLocktime(this.txPreimage) >= this.deadline);
                this.count++;
              }
            }
            """;
        Validate.Result result = validateSource(source);
        assertTrue(hasLocktimeWarning(result),
            "expected the locktime-soundness warning; got: " + result.warnings());
        List<String> matches = result.warnings().stream()
            .filter(w -> w.contains(WARNING_NEEDLE)).toList();
        String w = matches.get(0);
        // The warning names the method and points at the fix.
        assertTrue(w.contains("unlock"), "warning must name the method; got: " + w);
        assertTrue(w.contains("0xffffffff"), "warning must reference 0xffffffff; got: " + w);
    }

    @Test
    void doesNotWarnWhenMethodAlsoAssertsSequenceLessThanFinal() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              public unlock() {
                assert(extractSequence(this.txPreimage) < 0xffffffffn);
                assert(extractLocktime(this.txPreimage) >= this.deadline);
                this.count++;
              }
            }
            """;
        assertFalse(hasLocktimeWarning(validateSource(source)));
    }

    @Test
    void stillWarnsWhenSequenceComparisonIsNegated() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              public unlock() {
                assert(!(extractSequence(this.txPreimage) !== 0xffffffffn));
                assert(extractLocktime(this.txPreimage) >= this.deadline);
                this.count++;
              }
            }
            """;
        assertTrue(hasLocktimeWarning(validateSource(source)),
            "negated sequence comparison must not count as a guard");
    }

    @Test
    void doesNotWarnForMethodThatNeverReadsLocktime() throws TsParser.ParseException {
        String source = """
            class Counter extends StatefulSmartContract {
              count: bigint;
              constructor(count: bigint) {
                super(count);
                this.count = count;
              }
              public increment() {
                this.count++;
              }
            }
            """;
        assertFalse(hasLocktimeWarning(validateSource(source)));
    }

    @Test
    void seesSequenceGuardSuppliedTransitivelyThroughPrivateHelper() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              private requireNonFinal() {
                assert(extractSequence(this.txPreimage) < 0xffffffffn);
              }
              public unlock() {
                this.requireNonFinal();
                assert(extractLocktime(this.txPreimage) >= this.deadline);
                this.count++;
              }
            }
            """;
        assertFalse(hasLocktimeWarning(validateSource(source)));
    }

    @Test
    void warnsWhenLocktimeReadIsInPrivateHelperButNoSequenceGuardExists() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              private checkDeadline() {
                assert(extractLocktime(this.txPreimage) >= this.deadline);
              }
              public unlock() {
                this.checkDeadline();
                this.count++;
              }
            }
            """;
        assertTrue(hasLocktimeWarning(validateSource(source)),
            "expected the locktime-soundness warning; got: "
                + validateSource(source).warnings());
    }

    @Test
    void warnsWhenComparisonIsAssignedNotAsserted() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              public unlock() {
                const ok: boolean = extractSequence(this.txPreimage) !== 0xffffffffn;
                assert(extractLocktime(this.txPreimage) >= this.deadline);
                this.count++;
              }
            }
            """;
        assertTrue(hasLocktimeWarning(validateSource(source)),
            "assigned comparison must not silence the warning; got: "
                + validateSource(source).warnings());
    }

    @Test
    void warnsForVacuousStrictBound() throws TsParser.ParseException {
        String source = """
            class TimeLock extends StatefulSmartContract {
              count: bigint;
              readonly deadline: bigint;
              constructor(count: bigint, deadline: bigint) {
                super(count, deadline);
                this.count = count;
                this.deadline = deadline;
              }
              public unlock() {
                assert(extractSequence(this.txPreimage) < 0n);
                assert(extractLocktime(this.txPreimage) >= this.deadline);
                this.count++;
              }
            }
            """;
        assertTrue(hasLocktimeWarning(validateSource(source)),
            "extractSequence < 0n is not a finality guard; got: "
                + validateSource(source).warnings());
    }
}
