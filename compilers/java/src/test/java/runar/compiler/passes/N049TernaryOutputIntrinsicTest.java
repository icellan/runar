package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm.
 *
 * <p>{@code AnfLower.lowerTernaryExpr} lowers each arm into a sub-context whose
 * output refs are dropped, unlike the if-statement lowering, which merges each
 * arm's refs into the parent. The continuation hash therefore omitted the arm's
 * output: measured on every tier, a spend that drops the payee output was
 * accepted and the honest spend rejected. Fail-closed like R-127: the validator
 * refuses an output intrinsic (direct, or through an inlined private helper) in
 * either arm with the shared N-049 diagnostic, and pass 4 refuses it again when
 * reached unvalidated.
 *
 * <p>What this proves: this tier refuses the ternary-arm shapes at pass 2 and
 * pass 4 with the shared diagnostic, and still accepts and lowers a ternary
 * that only selects VALUES.
 * What it does not prove: anything about emitted bytes (the cross-tier control
 * is conformance/negatives/ternary-output-control.test.ts).
 */
class N049TernaryOutputIntrinsicTest {

    private static final String HEAD = """
        import { StatefulSmartContract, ByteString } from 'runar-lang';

        class ConditionalPayout extends StatefulSmartContract {
          count: bigint;
          readonly payee: ByteString;
          readonly refund: ByteString;

          constructor(count: bigint, payee: ByteString, refund: ByteString) {
            super(count, payee, refund);
            this.count = count;
            this.payee = payee;
            this.refund = refund;
          }
        """;

    private static final String TERNARY_ARMS = """
          public release() {
            this.addOutput(1000n, this.count);
            this.count > 0n ? this.addRawOutput(50000n, this.payee)
                            : this.addRawOutput(50000n, this.refund);
          }
        """;

    private static final String VALUE_SELECTING = """
          public release() {
            this.addOutput(1000n, this.count);
            this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
          }
        """;

    private static final String REFUSAL =
        "Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm.";

    private static ContractNode parse(String methods) throws Exception {
        return ParserDispatch.parse(HEAD + methods + "\n}\n", "ConditionalPayout.runar.ts");
    }

    private static List<String> errors(String methods) throws Exception {
        return Validate.runCollecting(parse(methods)).errors();
    }

    @Test
    void validatorRefusesOutputIntrinsicInTernaryArm() throws Exception {
        List<String> errs = errors(TERNARY_ARMS);
        assertTrue(errs.stream().anyMatch(m -> m.contains(REFUSAL)),
            "not refused with the N-049 diagnostic: " + errs);
    }

    @Test
    void validatorRefusesHelperOutputInTernaryArm() throws Exception {
        List<String> errs = errors("""
              public release() {
                this.addOutput(1000n, this.count);
                this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
              }

              private payTo(script: ByteString): void {
                this.addRawOutput(50000n, script);
              }
            """);
        String want = "Output intrinsic 'addRawOutput' (reached through private method 'payTo')"
            + " cannot be called inside a conditional (ternary) expression arm.";
        assertTrue(errs.stream().anyMatch(m -> m.contains(want)),
            "not refused with the N-049 diagnostic: " + errs);
    }

    @Test
    void loweringRefusesTernaryArmOutputWithoutValidation() throws Exception {
        ContractNode contract = parse(TERNARY_ARMS);
        IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () -> AnfLower.run(contract),
            "AnfLower accepted an output intrinsic inside a ternary arm");
        assertTrue(e.getMessage().contains(REFUSAL),
            "refused, but not with the N-049 diagnostic: " + e.getMessage());
    }

    @Test
    void valueSelectingTernaryStillAccepted() throws Exception {
        assertEquals(List.of(), errors(VALUE_SELECTING));
        ContractNode contract = parse(VALUE_SELECTING);
        assertDoesNotThrow(() -> AnfLower.run(contract));
    }
}
