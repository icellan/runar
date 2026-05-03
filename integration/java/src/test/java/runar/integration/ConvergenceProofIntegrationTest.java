package runar.integration;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.runtime.MockCrypto;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * End-to-end regtest tests for {@code ConvergenceProof} -- a stateless
 * contract using EC point operations. Verifies R_A - R_B = deltaO * G
 * on secp256k1, proving two OPRF submissions share an underlying token.
 *
 * <p>Ported from {@code integration/python/test_convergence_proof.py}.
 */
class ConvergenceProofIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/convergence-proof/ConvergenceProof.runar.ts";

    private static String[] testData() {
        long a = 12345L;
        long b = 6789L;
        BigInteger n = MockCrypto.EC_N;
        BigInteger delta = BigInteger.valueOf(a - b).mod(n);
        BigInteger wrong = BigInteger.valueOf(a - b + 1L).mod(n);

        MockCrypto.Point ra = MockCrypto.ecMulGen(BigInteger.valueOf(a));
        MockCrypto.Point rb = MockCrypto.ecMulGen(BigInteger.valueOf(b));
        return new String[] {
            ra.toHex(), rb.toHex(), delta.toString(), wrong.toString()
        };
    }

    @Test
    @DisplayName("deploy with valid EC points")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);
        String[] td = testData();

        RunarContract contract = new RunarContract(a, List.of(td[0], td[1]));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 5_000L);
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("spend with valid deltaO")
    void spendValidDelta() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);
        String[] td = testData();

        RunarContract contract = new RunarContract(a, List.of(td[0], td[1]));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome call = contract.call(
            "proveConvergence", List.of(new BigInteger(td[2])), null, provider, wallet.signer()
        );
        assertNotNull(call.txid());
    }

    @Test
    @DisplayName("invalid deltaO rejected by node")
    void spendInvalidDeltaRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);
        String[] td = testData();

        RunarContract contract = new RunarContract(a, List.of(td[0], td[1]));
        contract.deploy(provider, wallet.signer(), 5_000L);

        assertThrows(RuntimeException.class, () ->
            contract.call(
                "proveConvergence", List.of(new BigInteger(td[3])), null, provider, wallet.signer()
            )
        );
    }

    @Test
    @DisplayName("Java-surface ConvergenceProof matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/convergence-proof/ConvergenceProof.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
