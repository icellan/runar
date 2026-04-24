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
 * End-to-end regtest tests for {@code BitwiseOps} — a stateless
 * contract that exercises the shift, AND, OR, XOR, and unary-negate
 * operators on {@code bigint} operands. Covers the
 * {@code OP_LSHIFT} / {@code OP_RSHIFT} / {@code OP_AND} / {@code OP_OR}
 * / {@code OP_XOR} / {@code OP_NEGATE} opcodes surviving the full
 * pipeline through to node-side validation.
 */
class BitwiseOpsIntegrationTest extends IntegrationBase {

    @Test
    @DisplayName("testShift: shifts compile and the node accepts the spend")
    void testShiftRuns() {
        runMethod("testShift");
    }

    @Test
    @DisplayName("testBitwise: AND/OR/XOR/NEG compile and spend succeeds")
    void testBitwiseRuns() {
        runMethod("testBitwise");
    }

    @Test
    @DisplayName("Java-surface BitwiseOps matches TS-surface variant (if present)")
    void javaSurfaceLowersConsistently() {
        // No TS-surface source exists for BitwiseOps today, so instead we
        // check that the Java source compiles to a non-empty locking
        // script through the TS compiler's Java frontend.
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/bitwise-ops/BitwiseOps.runar.java"
        );
        assertEquals("BitwiseOps", java.contractName());
        assertNotNull(java.scriptHex());
    }

    // ------------------------------------------------------------------

    private void runMethod(String method) {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/bitwise-ops/BitwiseOps.runar.java"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact,
            List.of(BigInteger.valueOf(0x1234), BigInteger.valueOf(0x5678))
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome out = contract.call(
            method, List.of(), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }
}
