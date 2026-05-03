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
 * SPHINCSWallet integration test -- Hybrid ECDSA + SLH-DSA-SHA2-128s
 * contract. Deploy-only coverage; the full two-pass spend requires raw
 * transaction construction (Go {@code TestSLHDSA_ValidSpend} owns the
 * full spend coverage).
 *
 * <p>Ported from {@code integration/python/test_sphincs_wallet.py}.
 */
class SphincsWalletIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts";

    // Same deterministic 32-byte SLH-DSA test PK used by the Python suite.
    private static final String SLHDSA_TEST_PK_HEX =
        "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf";

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

    private static byte[] fromHex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Test
    @DisplayName("compile produces an SPHINCSWallet artifact ~188KB")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("SPHINCSWallet", a.contractName());
        int scriptBytes = a.scriptHex().length() / 2;
        assert scriptBytes > 100_000 && scriptBytes < 500_000
            : "expected SPHINCSWallet script ~188KB, got " + scriptBytes;
    }

    @Test
    @DisplayName("deploy with ECDSA pubkey hash + SLH-DSA pubkey hash")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        String slhdsaPkHash = hash160Hex(fromHex(SLHDSA_TEST_PK_HEX));

        RunarContract contract = new RunarContract(a, List.of(
            wallet.pubKeyHash(), slhdsaPkHash
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 50_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("Java-surface SPHINCSWallet matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/sphincs-wallet/SPHINCSWallet.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
