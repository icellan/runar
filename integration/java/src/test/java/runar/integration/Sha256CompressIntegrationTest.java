package runar.integration;

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
 * SHA-256 compression integration test -- stateless contract verifying
 * {@code sha256Compress(state, block) == expected}.
 *
 * <p>Ported from {@code integration/ts/sha256-compress.test.ts}
 * (single-block subset). The test computes SHA-256("abc") via the
 * Java SDK's {@link MockCrypto} and pins the on-chain result.
 */
class Sha256CompressIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/sha256-compress/Sha256CompressTest.runar.ts";

    private static final String SHA256_INIT =
        "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";

    /** Pad message per FIPS 180-4 5.1.1: append 0x80, zero-pad to 56, 8-byte BE bit length. */
    private static String padOneBlock(String msgHex) {
        int msgBytes = msgHex.length() / 2;
        long bitLen = (long) msgBytes * 8L;
        StringBuilder padded = new StringBuilder(msgHex);
        padded.append("80");
        while ((padded.length() / 2) % 64 != 56) padded.append("00");
        padded.append(String.format("%016x", bitLen));
        return padded.toString();
    }

    @Test
    @DisplayName("sha256Compress: 'abc' single-block matches MockCrypto reference")
    void compressAbc() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        String msgHex = "616263"; // "abc"
        String paddedHex = padOneBlock(msgHex);

        ByteString state = ByteString.fromHex(SHA256_INIT);
        ByteString block = ByteString.fromHex(paddedHex);
        ByteString expected = MockCrypto.sha256Compress(state, block);

        RunarContract contract = new RunarContract(a, List.of(expected.toHex()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome out = contract.call(
            "verify", List.of(SHA256_INIT, paddedHex), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("Java-surface Sha256CompressTest matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/sha256-compress/Sha256CompressTest.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
