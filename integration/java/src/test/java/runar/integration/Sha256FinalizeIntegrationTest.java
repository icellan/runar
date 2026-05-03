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
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * SHA-256 finalize integration test -- stateless contract verifying
 * {@code sha256Finalize(state, remaining, msgBitLen) == expected}.
 * Used to verify the last block of a multi-block SHA-256 computation.
 *
 * <p>Ported from {@code integration/ts/sha256-finalize.test.ts}.
 */
class Sha256FinalizeIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts";

    private static final String SHA256_INIT =
        "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";

    @Test
    @DisplayName("sha256Finalize: 'abc' from initial state matches MockCrypto reference")
    void finalizeAbc() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        // 3-byte "abc" — fits inside the finalize remaining bytes.
        String remainingHex = "616263";
        long bitLen = 24L;

        ByteString state = ByteString.fromHex(SHA256_INIT);
        ByteString remaining = ByteString.fromHex(remainingHex);
        ByteString expected = MockCrypto.sha256Finalize(state, remaining, BigInteger.valueOf(bitLen));

        RunarContract contract = new RunarContract(a, List.of(expected.toHex()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome out = contract.call(
            "verify",
            List.of(SHA256_INIT, remainingHex, BigInteger.valueOf(bitLen)),
            null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("Java-surface Sha256FinalizeTest matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/sha256-finalize/Sha256FinalizeTest.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
