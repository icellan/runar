package runar.integration;

import java.math.BigInteger;
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
 * SchnorrZKP integration test -- stateless contract verifying
 * {@code s*G == R + e*P}. Tests both compile-only and the full
 * deploy + verify-with-valid-proof path.
 *
 * <p>Ported from {@code integration/python/test_schnorr_zkp.py}.
 */
class SchnorrZkpIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/schnorr-zkp/SchnorrZKP.runar.ts";

    /**
     * Fiat-Shamir challenge: e = bin2num(hash256(R || P)).
     * hash256 = double-SHA256; bin2num is little-endian signed-magnitude.
     */
    private static BigInteger fiatShamirChallenge(String rHex, String pHex) {
        try {
            byte[] combined = fromHex(rHex + pHex);
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] h1 = sha.digest(combined);
            sha.reset();
            byte[] h2 = sha.digest(h1);
            // bin2num: LE signed-magnitude. h2 is 32 bytes.
            boolean neg = (h2[31] & 0x80) != 0;
            byte[] bytes = h2.clone();
            bytes[31] &= 0x7f;
            // LE -> BigInteger
            byte[] beReversed = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) beReversed[i] = bytes[bytes.length - 1 - i];
            BigInteger mag = new BigInteger(1, beReversed);
            return neg ? mag.negate() : mag;
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
    @DisplayName("compile produces a SchnorrZKP artifact (~877KB)")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("SchnorrZKP", a.contractName());
    }

    @Test
    @DisplayName("deploy with EC public key point")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        BigInteger k = BigInteger.valueOf(42);
        MockCrypto.Point p = MockCrypto.ecMulGen(k);

        RunarContract contract = new RunarContract(a, List.of(p.toHex()));
        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 50_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("verify with valid Schnorr ZKP proof: s*G = R + e*P")
    void verifyValidProof() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        BigInteger k = BigInteger.valueOf(42);
        MockCrypto.Point pubKey = MockCrypto.ecMulGen(k);
        String pHex = pubKey.toHex();

        RunarContract contract = new RunarContract(a, List.of(pHex));
        contract.deploy(provider, wallet.signer(), 50_000L);

        BigInteger r = BigInteger.valueOf(7777);
        MockCrypto.Point rPoint = MockCrypto.ecMulGen(r);
        String rHex = rPoint.toHex();

        BigInteger e = fiatShamirChallenge(rHex, pHex);
        // s = r + e*k mod n
        BigInteger s = r.add(e.multiply(k)).mod(MockCrypto.EC_N);

        RunarContract.CallOutcome call = contract.call(
            "verify", List.of(rHex, s), null, provider, wallet.signer()
        );
        assertNotNull(call.txid());
    }

    @Test
    @DisplayName("Java-surface SchnorrZKP matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/schnorr-zkp/SchnorrZKP.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
