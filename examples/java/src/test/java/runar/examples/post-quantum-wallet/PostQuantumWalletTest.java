package runar.examples.postquantumwallet;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Instantiation and {@code spend} tests for {@link PostQuantumWallet}.
 *
 * <p>{@code verifyWOTS} IS implemented in
 * {@link runar.lang.runtime.MockCrypto#verifyWOTS}: a real RFC 8391 WOTS+
 * verifier (w=16, n=32), not a stub. {@link #spendSucceedsWithHonestWotsSignature}
 * and {@link #spendFailsOnTamperedWotsSignature} exercise it through the
 * simulator: a WOTS+ keypair is generated with
 * {@link MockCrypto#wotsKeygenDeterministic} and a signature produced with
 * {@link MockCrypto#wotsSign} over the ECDSA signature bytes (the message
 * {@code spend} feeds to {@code verifyWOTS}), then {@code spend} is called
 * through {@link ContractSimulator}. The {@code checkSig} call inside
 * {@code spend} is still mocked to a null-check (see {@link MockCrypto#checkSig}),
 * so these tests do not exercise real ECDSA — only the WOTS+ layer and the
 * real {@code hash160} commitments are genuine here. End-to-end cross-tier
 * conformance (including the ECDSA layer) is exercised through the other
 * compiler tiers via the shared conformance suite.
 */
class PostQuantumWalletTest {

    private static final PubKey PK = PubKey.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    @Test
    void contractInstantiates() {
        Addr ecdsaPubKeyHash = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        ByteString wotsPubKeyHash = ByteString.fromHex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4");
        PostQuantumWallet c = new PostQuantumWallet(ecdsaPubKeyHash, wotsPubKeyHash);
        assertNotNull(c);
        assertEquals(ecdsaPubKeyHash, c.ecdsaPubKeyHash);
        assertEquals(wotsPubKeyHash, c.wotsPubKeyHash);
    }

    @Test
    void spendSucceedsWithHonestWotsSignature() {
        Sig sig = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

        byte[] seed = "post-quantum-wallet-test-seed-01".getBytes();
        byte[] pubSeed = new byte[32];
        for (int i = 0; i < 32; i++) pubSeed[i] = (byte) i;
        byte[][] keys = MockCrypto.wotsKeygenDeterministic(seed, pubSeed);
        byte[] wotsSk = keys[0];
        byte[] wotsPk = keys[1];
        byte[] wotsSig = MockCrypto.wotsSign(sig.toByteArray(), wotsSk, pubSeed);

        Addr ecdsaPubKeyHash = MockCrypto.hash160(PK);
        ByteString wotsPubKeyHash = MockCrypto.hash160(new ByteString(wotsPk));
        PostQuantumWallet contract = new PostQuantumWallet(ecdsaPubKeyHash, wotsPubKeyHash);

        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertDoesNotThrow(() ->
            sim.call("spend", new ByteString(wotsSig), new ByteString(wotsPk), sig, PK));
    }

    /**
     * Proves {@code verifyWOTS} actually checks the signature rather than
     * always returning true: flipping one byte of an otherwise-honest WOTS+
     * signature must make {@code spend} fail.
     */
    @Test
    void spendFailsOnTamperedWotsSignature() {
        Sig sig = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

        byte[] seed = "post-quantum-wallet-test-seed-02".getBytes();
        byte[] pubSeed = new byte[32];
        for (int i = 0; i < 32; i++) pubSeed[i] = (byte) (i + 1);
        byte[][] keys = MockCrypto.wotsKeygenDeterministic(seed, pubSeed);
        byte[] wotsSk = keys[0];
        byte[] wotsPk = keys[1];
        byte[] wotsSig = MockCrypto.wotsSign(sig.toByteArray(), wotsSk, pubSeed);
        wotsSig[0] ^= 0x01;

        Addr ecdsaPubKeyHash = MockCrypto.hash160(PK);
        ByteString wotsPubKeyHash = MockCrypto.hash160(new ByteString(wotsPk));
        PostQuantumWallet contract = new PostQuantumWallet(ecdsaPubKeyHash, wotsPubKeyHash);

        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertThrows(AssertionError.class, () ->
            sim.call("spend", new ByteString(wotsSig), new ByteString(wotsPk), sig, PK));
    }
}
