package runar.examples.convergenceproof;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.ecAdd;
import static runar.lang.Builtins.ecMulGen;
import static runar.lang.Builtins.ecNegate;
import static runar.lang.Builtins.ecOnCurve;
import static runar.lang.Builtins.ecPointX;
import static runar.lang.Builtins.ecPointY;

/**
 * ConvergenceProof -- OPRF-based fraud signal convergence proof.
 *
 * <p>Ports {@code examples/python/convergence-proof/ConvergenceProof.runar.py}
 * to Java.
 *
 * <p>Two parties submit randomized tokens
 * {@code R_A = (T + o_A)*G} and {@code R_B = (T + o_B)*G} where {@code T}
 * is the shared underlying token and {@code o_A, o_B} are ECDH-derived
 * offsets.
 *
 * <p>An authority who knows both offsets can prove the two submissions
 * share the same token {@code T} by providing
 * {@code delta_o = o_A - o_B} and verifying:
 * <pre>
 *     R_A - R_B = delta_o * G
 * </pre>
 *
 * <p>The token {@code T} cancels out in the subtraction, proving
 * convergence without revealing {@code T}. Spending this UTXO serves as a
 * formal on-chain subpoena trigger.
 *
 * <p>The EC-typed fields use {@link MockCrypto.Point} (the simulator's
 * coordinate-form representation) so the contract's body composes with
 * the {@code ec*} builtins exposed by {@link runar.lang.Builtins}; the
 * Rúnar parser maps this to the {@code Point} primitive in the IR.
 */
class ConvergenceProof extends SmartContract {

    @Readonly MockCrypto.Point rA;
    @Readonly MockCrypto.Point rB;

    ConvergenceProof(MockCrypto.Point rA, MockCrypto.Point rB) {
        super(rA, rB);
        this.rA = rA;
        this.rB = rB;
    }

    /** Prove convergence via offset difference. */
    @Public
    void proveConvergence(Bigint deltaO) {
        // Verify both committed points are on the curve.
        assertThat(ecOnCurve(this.rA));
        assertThat(ecOnCurve(this.rB));

        // R_A - R_B (point subtraction = addition with negated second operand).
        MockCrypto.Point diff = ecAdd(this.rA, ecNegate(this.rB));

        // delta_o * G (scalar multiplication of generator).
        MockCrypto.Point expected = ecMulGen(deltaO.value());

        // Assert point equality via coordinate comparison.
        assertThat(ecPointX(diff).equals(ecPointX(expected)));
        assertThat(ecPointY(diff).equals(ecPointY(expected)));
    }
}
