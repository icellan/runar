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
 * P256Wallet integration test -- stateless hybrid ECDSA + P-256 wallet.
 * Deploy-only coverage; the full hybrid spend path requires raw P-256
 * signing and is mirrored by the Go {@code TestP256Wallet_Spend} suite.
 *
 * <p>Ported from {@code integration/ts/p256-wallet.test.ts} (deploy
 * subset).
 */
class P256WalletIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/p256-wallet/P256Wallet.runar.ts";

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
    @DisplayName("compile produces a P256Wallet artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("P256Wallet", a.contractName());
    }

    @Test
    @DisplayName("deploy with ECDSA pubKeyHash + P-256 pubKeyHash")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        // Deterministic 33-byte P-256 compressed pubkey placeholder. The
        // contract only commits to its hash160 — no signing is performed
        // in this deploy test.
        byte[] p256Pk = new byte[33];
        p256Pk[0] = 0x02;
        for (int i = 1; i < 33; i++) p256Pk[i] = (byte) i;
        String p256PkHash = hash160Hex(p256Pk);

        RunarContract contract = new RunarContract(a, List.of(
            wallet.pubKeyHash(), p256PkHash
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 10_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("Java-surface P256Wallet matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/p256-wallet/P256Wallet.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
