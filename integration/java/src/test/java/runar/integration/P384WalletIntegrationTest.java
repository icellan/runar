package runar.integration;

import java.security.MessageDigest;
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
 * P384Wallet integration test -- stateless hybrid ECDSA + P-384 wallet.
 * Deploy-only coverage; the full hybrid spend path requires raw P-384
 * signing and is mirrored by the Go suite.
 *
 * <p>Ported from {@code integration/ts/p384-wallet.test.ts}
 * (deploy subset).
 */
class P384WalletIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/p384-wallet/P384Wallet.runar.ts";

    private static String hash160Hex(byte[] data) {
        try {
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(data);
            org.bouncycastle.crypto.digests.RIPEMD160Digest ripe =
                new org.bouncycastle.crypto.digests.RIPEMD160Digest();
            ripe.update(sha, 0, sha.length);
            byte[] out = new byte[20];
            ripe.doFinal(out, 0);
            StringBuilder sb = new StringBuilder(40);
            for (byte b : out) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("compile produces a P384Wallet artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("P384Wallet", a.contractName());
    }

    @Test
    @DisplayName("deploy with ECDSA pubKeyHash + P-384 pubKeyHash")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        byte[] p384Pk = new byte[49];
        p384Pk[0] = 0x02;
        for (int i = 1; i < 49; i++) p384Pk[i] = (byte) (i + 1);
        String p384PkHash = hash160Hex(p384Pk);

        RunarContract contract = new RunarContract(a, List.of(
            wallet.pubKeyHash(), p384PkHash
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 10_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("Java-surface P384Wallet matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/p384-wallet/P384Wallet.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
