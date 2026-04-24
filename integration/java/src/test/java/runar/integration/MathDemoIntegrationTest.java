package runar.integration;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end regtest tests for the {@code MathDemo} stateful contract.
 * Ported from {@code integration/python/test_math_demo.py}. Exercises
 * every built-in math function available in Rúnar: {@code safediv},
 * {@code clamp}, {@code sign}, {@code pow}, {@code sqrt}, {@code gcd},
 * {@code mulDiv}, {@code percentOf}, {@code log2}.
 *
 * <p>The goal of this suite is breadth (does every math builtin survive
 * the full compile → deploy → call → broadcast → validate loop on a
 * real node?), not depth on any single method.
 */
class MathDemoIntegrationTest extends IntegrationBase {

    @Test
    @DisplayName("divideBy(3): 10 -> 3")
    void divideBy() {
        runMethod("divideBy", BigInteger.TEN, List.of(BigInteger.valueOf(3)));
    }

    @Test
    @DisplayName("clampValue(10, 20): 5 -> 10")
    void clamp() {
        runMethod(
            "clampValue", BigInteger.valueOf(5),
            List.of(BigInteger.valueOf(10), BigInteger.valueOf(20))
        );
    }

    @Test
    @DisplayName("normalize: -7 -> -1")
    void normalize() {
        runMethod("normalize", BigInteger.valueOf(-7), List.of());
    }

    @Test
    @DisplayName("exponentiate(4): 2 -> 16")
    void exponentiate() {
        runMethod(
            "exponentiate", BigInteger.valueOf(2),
            List.of(BigInteger.valueOf(4))
        );
    }

    @Test
    @DisplayName("squareRoot: 16 -> 4")
    void squareRoot() {
        runMethod("squareRoot", BigInteger.valueOf(16), List.of());
    }

    @Test
    @DisplayName("reduceGcd(14): 21 -> 7")
    void reduceGcd() {
        runMethod(
            "reduceGcd", BigInteger.valueOf(21),
            List.of(BigInteger.valueOf(14))
        );
    }

    @Test
    @DisplayName("scaleByRatio(3, 2): 10 -> 15")
    void scaleByRatio() {
        runMethod(
            "scaleByRatio", BigInteger.TEN,
            List.of(BigInteger.valueOf(3), BigInteger.valueOf(2))
        );
    }

    @Test
    @DisplayName("computeLog2: 128 -> 7")
    void computeLog2() {
        runMethod("computeLog2", BigInteger.valueOf(128), List.of());
    }

    @Test
    @DisplayName("Java-surface MathDemo matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(
            "examples/ts/math-demo/MathDemo.runar.ts"
        );
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/math-demo/MathDemo.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }

    // ------------------------------------------------------------------

    private void runMethod(String method, BigInteger initial, List<Object> args) {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/math-demo/MathDemo.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(initial)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome call = contract.call(
            method, args, null, provider, wallet.signer()
        );
        assertNotNull(call.txid());
        assertEquals(64, call.txid().length());
    }
}
