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
 * BLAKE3 integration test -- stateless contract verifying that
 * {@code blake3Hash(msg) == expected}. Uses the Java SDK's
 * {@link MockCrypto#blake3Hash} (real BLAKE3) to precompute the
 * digest committed to in the constructor.
 *
 * <p>Ported from {@code integration/ts/blake3.test.ts} (subset).
 */
class Blake3IntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/blake3/Blake3Test.runar.ts";

    private static String hexAscii(String s) {
        StringBuilder sb = new StringBuilder(s.length() * 2);
        for (char c : s.toCharArray()) sb.append(String.format("%02x", (int) c & 0xff));
        return sb.toString();
    }

    @Test
    @DisplayName("blake3Hash: deploy + spend with 'abc' digest")
    void hashAbc() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        String msgHex = hexAscii("abc");
        ByteString msgBs = ByteString.fromHex(msgHex);
        ByteString expected = MockCrypto.blake3Hash(msgBs);

        RunarContract contract = new RunarContract(a, List.of(expected.toHex()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome out = contract.call(
            "verifyHash", List.of(msgHex), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("Java-surface Blake3Test matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/blake3/Blake3Test.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
