package runar.examples.sphincswallet;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.SlhDsa;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Instantiation and {@code spend} tests for {@link SPHINCSWallet}.
 *
 * <p>{@code verifySLHDSA_SHA2_128s} IS implemented in
 * {@link runar.lang.runtime.MockCrypto#verifySLHDSA_SHA2_128s}: a real FIPS
 * 205 SLH-DSA-SHA2-128s verifier, not a stub. {@link #spendSucceedsWithHonestSlhDsaSignature}
 * and {@link #spendFailsOnTamperedSlhDsaSignature} exercise it through the
 * simulator: an SLH-DSA keypair is generated with {@link SlhDsa#keygen} and
 * a signature produced with {@link SlhDsa#sign} over the ECDSA signature
 * bytes (the message {@code spend} feeds to {@code verifySLHDSA_SHA2_128s}),
 * then {@code spend} is called through {@link ContractSimulator}. The
 * {@code checkSig} call inside {@code spend} is still mocked to a null-check
 * (see {@link MockCrypto#checkSig}), so these tests do not exercise real
 * ECDSA — only the SLH-DSA layer and the real {@code hash160} commitments
 * are genuine here. End-to-end cross-tier conformance (including the ECDSA
 * layer) is exercised through the other compiler tiers via the shared
 * conformance suite.
 */
class SPHINCSWalletTest {

    private static final PubKey PK = PubKey.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    @Test
    void contractInstantiates() {
        Addr ecdsaPubKeyHash = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        ByteString slhdsaPubKeyHash = ByteString.fromHex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4");
        SPHINCSWallet c = new SPHINCSWallet(ecdsaPubKeyHash, slhdsaPubKeyHash);
        assertNotNull(c);
        assertEquals(ecdsaPubKeyHash, c.ecdsaPubKeyHash);
        assertEquals(slhdsaPubKeyHash, c.slhdsaPubKeyHash);
    }

    @Test
    void spendSucceedsWithHonestSlhDsaSignature() {
        Sig sig = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

        byte[] seed = deterministicSeed((byte) 0x01);
        SlhDsa.KeyPair kp = SlhDsa.keygen(SlhDsa.SHA2_128s, seed);
        byte[] slhdsaSig = SlhDsa.sign(SlhDsa.SHA2_128s, sig.toByteArray(), kp.sk);

        Addr ecdsaPubKeyHash = MockCrypto.hash160(PK);
        ByteString slhdsaPubKeyHash = MockCrypto.hash160(new ByteString(kp.pk));
        SPHINCSWallet contract = new SPHINCSWallet(ecdsaPubKeyHash, slhdsaPubKeyHash);

        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertDoesNotThrow(() ->
            sim.call("spend", new ByteString(slhdsaSig), new ByteString(kp.pk), sig, PK));
    }

    /**
     * Proves {@code verifySLHDSA_SHA2_128s} actually checks the signature
     * rather than always returning true: flipping one byte of an otherwise-
     * honest SLH-DSA signature must make {@code spend} fail.
     */
    @Test
    void spendFailsOnTamperedSlhDsaSignature() {
        Sig sig = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

        byte[] seed = deterministicSeed((byte) 0x02);
        SlhDsa.KeyPair kp = SlhDsa.keygen(SlhDsa.SHA2_128s, seed);
        byte[] slhdsaSig = SlhDsa.sign(SlhDsa.SHA2_128s, sig.toByteArray(), kp.sk);
        slhdsaSig[0] ^= 0x01;

        Addr ecdsaPubKeyHash = MockCrypto.hash160(PK);
        ByteString slhdsaPubKeyHash = MockCrypto.hash160(new ByteString(kp.pk));
        SPHINCSWallet contract = new SPHINCSWallet(ecdsaPubKeyHash, slhdsaPubKeyHash);

        ContractSimulator sim = ContractSimulator.stateless(contract);
        assertThrows(AssertionError.class, () ->
            sim.call("spend", new ByteString(slhdsaSig), new ByteString(kp.pk), sig, PK));
    }

    /** {@code SlhDsa.keygen(SHA2_128s, seed)} requires a 3*n = 48-byte seed. */
    private static byte[] deterministicSeed(byte tag) {
        byte[] seed = new byte[48];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (tag + i);
        return seed;
    }
}
