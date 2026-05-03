package runar.integration;

import java.security.MessageDigest;
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
 * PostQuantumWallet integration test -- Hybrid ECDSA + WOTS+ contract.
 * Deploy-only coverage; the full two-pass WOTS spend flow requires raw
 * transaction construction (covered by Go {@code TestWOTS_ValidSpend}
 * and not yet wired through the Java SDK's generic {@code call()}).
 *
 * <p>Ported from {@code integration/python/test_post_quantum_wallet.py}.
 */
class PostQuantumWalletIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts";

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
    @DisplayName("compile produces a PostQuantumWallet artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("PostQuantumWallet", a.contractName());
        // Hybrid ECDSA+WOTS scripts are roughly 10 KB.
        int scriptBytes = a.scriptHex().length() / 2;
        assert scriptBytes > 5_000 && scriptBytes < 50_000
            : "expected PostQuantumWallet script ~10KB, got " + scriptBytes;
    }

    @Test
    @DisplayName("deploy with ECDSA pubkey hash + WOTS+ pubkey hash")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        // Deterministic WOTS+ keypair (seed=0x42..., pubSeed=0x01...).
        byte[] seed = new byte[32]; seed[0] = 0x42;
        byte[] pubSeed = new byte[32]; pubSeed[0] = 0x01;
        byte[][] kp = MockCrypto.wotsKeygenDeterministic(seed, pubSeed);
        // kp[0] is sk-flat, kp[1] is pk (64 bytes: pubSeed||pkRoot).
        String wotsPkHash = hash160Hex(kp[1]);

        RunarContract contract = new RunarContract(a, List.of(
            wallet.pubKeyHash(), wotsPkHash
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 10_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("Java-surface PostQuantumWallet matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/post-quantum-wallet/PostQuantumWallet.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
