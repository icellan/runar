package runar.integration;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
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

/**
 * EC isolation integration tests -- inline contracts exercising one
 * EC built-in each. Ported from
 * {@code integration/python/test_ec_isolation.py} (subset).
 *
 * <p>The Java SDK's {@link MockCrypto#ecMulGen} uses BouncyCastle's
 * secp256k1 implementation when BC is on the classpath (it is via
 * runar-java), so generated points are real curve points the on-chain
 * EC verification accepts.
 */
class EcIsolationIntegrationTest extends IntegrationBase {

    private static RunarArtifact compileSource(String source, String fileName) {
        Path tmp;
        try {
            tmp = Files.createTempFile("runar-ec-isolation-", fileName);
            Files.writeString(tmp, source);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ContractCompiler.compileAbsolute(tmp);
    }

    @Test
    @DisplayName("ecOnCurve: deploy + spend with G*42")
    void ecOnCurve() {
        String source = """
            import { SmartContract, assert, ecOnCurve } from 'runar-lang';
            import type { Point } from 'runar-lang';

            class EcOnCurveTest extends SmartContract {
              readonly p: Point;
              constructor(p: Point) {
                super(p);
                this.p = p;
              }
              public verify() {
                assert(ecOnCurve(this.p));
              }
            }
            """;
        RunarArtifact a = compileSource(source, "EcOnCurveTest.runar.ts");
        assertEquals("EcOnCurveTest", a.contractName());

        MockCrypto.Point pt = MockCrypto.ecMulGen(BigInteger.valueOf(42));
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(pt.toHex()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome call = contract.call(
            "verify", List.of(), null, provider, wallet.signer()
        );
        assertNotNull(call.txid());
    }
}
