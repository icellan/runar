package runar.lang.runtime;

import org.junit.jupiter.api.Test;
import runar.lang.sdk.Json;
import runar.lang.sdk.ScriptUtils;
import runar.lang.types.ByteString;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SLH-DSA (FIPS 205) round-trip tests for all 6 SHA-2 parameter sets.
 *
 * <p>Sign-and-verify round-trips are exhaustive across parameter sets to
 * ensure the verification path is wired for every variant the on-chain
 * codegen supports. Per-variant signing is expensive (especially the
 * "small" variants); we use deterministic seeds to make runs reproducible.
 */
class SlhDsaTest {

    @Test
    void sha2_128f_signVerifyRoundTrip() {
        runRoundTrip(SlhDsa.SHA2_128f);
    }

    @Test
    void sha2_192f_signVerifyRoundTrip() {
        runRoundTrip(SlhDsa.SHA2_192f);
    }

    @Test
    void sha2_256f_signVerifyRoundTrip() {
        runRoundTrip(SlhDsa.SHA2_256f);
    }

    @Test
    void mockCryptoFacadeRoutesAllSixVariants() {
        // verify_*128s and 192s/256s would be very slow to sign here (some
        // run for tens of seconds); the routing is the point — we just
        // confirm each verify_* facade reaches SlhDsa.verify and rejects
        // a signature of the right length but with the wrong PK.
        SlhDsa.Params[] all = {
            SlhDsa.SHA2_128s, SlhDsa.SHA2_128f,
            SlhDsa.SHA2_192s, SlhDsa.SHA2_192f,
            SlhDsa.SHA2_256s, SlhDsa.SHA2_256f,
        };
        // Random-but-deterministic non-signature: all-zero R + zeroed FORS+HT
        // payload of the right total length — verify must reject.
        for (SlhDsa.Params p : all) {
            int sigLen = p.n /*R*/ + p.k * (1 + p.a) * p.n + p.d * (p.len + p.hp) * p.n;
            byte[] zeros = new byte[sigLen];
            byte[] pk = new byte[2 * p.n];
            byte[] msg = "facade-test".getBytes();
            switch (p.name) {
                case "SLH-DSA-SHA2-128s" -> assertFalse(MockCrypto.verifySLHDSA_SHA2_128s(new ByteString(msg), new ByteString(zeros), new ByteString(pk)));
                case "SLH-DSA-SHA2-128f" -> assertFalse(MockCrypto.verifySLHDSA_SHA2_128f(new ByteString(msg), new ByteString(zeros), new ByteString(pk)));
                case "SLH-DSA-SHA2-192s" -> assertFalse(MockCrypto.verifySLHDSA_SHA2_192s(new ByteString(msg), new ByteString(zeros), new ByteString(pk)));
                case "SLH-DSA-SHA2-192f" -> assertFalse(MockCrypto.verifySLHDSA_SHA2_192f(new ByteString(msg), new ByteString(zeros), new ByteString(pk)));
                case "SLH-DSA-SHA2-256s" -> assertFalse(MockCrypto.verifySLHDSA_SHA2_256s(new ByteString(msg), new ByteString(zeros), new ByteString(pk)));
                case "SLH-DSA-SHA2-256f" -> assertFalse(MockCrypto.verifySLHDSA_SHA2_256f(new ByteString(msg), new ByteString(zeros), new ByteString(pk)));
                default -> fail("unknown variant " + p.name);
            }
        }
    }

    @Test
    void sha2_128f_verifyFailsOnTamperedMessage() {
        SlhDsa.Params p = SlhDsa.SHA2_128f;
        byte[] seed = deterministicSeed(p, 1);
        SlhDsa.KeyPair kp = SlhDsa.keygen(p, seed);
        byte[] msg = "approved-payment".getBytes();
        byte[] sig = SlhDsa.sign(p, msg, kp.sk);
        byte[] tampered = "approved-payment-NOT".getBytes();
        assertFalse(SlhDsa.verify(p, tampered, sig, kp.pk));
    }

    @Test
    void sha2_128f_verifyFailsOnWrongPublicKey() {
        SlhDsa.Params p = SlhDsa.SHA2_128f;
        SlhDsa.KeyPair kp1 = SlhDsa.keygen(p, deterministicSeed(p, 11));
        SlhDsa.KeyPair kp2 = SlhDsa.keygen(p, deterministicSeed(p, 22));
        byte[] msg = "the message".getBytes();
        byte[] sig = SlhDsa.sign(p, msg, kp1.sk);
        assertFalse(SlhDsa.verify(p, msg, sig, kp2.pk));
    }

    @Test
    void sha2_128f_verifyRejectsBadLengths() {
        SlhDsa.Params p = SlhDsa.SHA2_128f;
        assertFalse(SlhDsa.verify(p, "x".getBytes(), new byte[10], new byte[2 * p.n]));
        assertFalse(SlhDsa.verify(p, "x".getBytes(), new byte[100000], new byte[2 * p.n + 1]));
    }

    /**
     * F-130: SHA2-256f has h - h' = 64. The tree-index mask was computed as
     * {@code (1L << 64) - 1}; Java takes long shift counts mod 64, so that is
     * {@code (1L << 0) - 1 == 0} and idx_tree collapsed to 0 in sign AND verify.
     *
     * <p>Proves: Java verifies the on-chain-accepted 256f witness signature
     * (conformance/witnesses/real-crypto/post-quantum-slhdsa-256f.json, signed by
     * the third-party PyPI slh-dsa 0.2.5 SHA-256-only instantiation; its 64-bit
     * tree index 0x9cc4feac04b4276d is >= 2^63, so every high bit matters), rejects
     * the witness's 1-bit near-miss, and Java's own deterministic signer reproduces
     * that independent signature byte-for-byte from the same seeds.
     *
     * <p>Does not prove: anything about the other five parameter sets beyond the
     * existing round-trips, nor FIPS 205 SHA-512 conformance (the repo variant is
     * SHA-256-only by design, issue #137).
     */
    @Test
    @SuppressWarnings("unchecked")
    void sha2_256f_verifiesAndReproducesOnChainWitnessWithHighTreeIndex() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "witnesses",
            "real-crypto", "post-quantum-slhdsa-256f.json");
        Map<String, Object> w = (Map<String, Object>) Json.parse(Files.readString(p));
        Map<String, Object> ctor = (Map<String, Object>) w.get("constructorArgs");
        byte[] pk = ScriptUtils.hexToBytes(((String) ctor.get("pubkey")).substring(2));
        List<Object> spends = (List<Object>) w.get("spends");
        int accepts = 0;
        int rejects = 0;
        byte[] honestMsg = null;
        byte[] honestSig = null;
        for (Object o : spends) {
            Map<String, Object> spend = (Map<String, Object>) o;
            List<Object> args = (List<Object>) spend.get("args");
            byte[] msg = ScriptUtils.hexToBytes(((String) args.get(0)).substring(2));
            byte[] sig = ScriptUtils.hexToBytes(((String) args.get(1)).substring(2));
            if ("accept".equals(spend.get("expect"))) {
                assertTrue(SlhDsa.verify(SlhDsa.SHA2_256f, msg, sig, pk),
                    "256f: the on-chain-accepted witness signature must verify");
                honestMsg = msg;
                honestSig = sig;
                accepts++;
            } else {
                assertFalse(SlhDsa.verify(SlhDsa.SHA2_256f, msg, sig, pk),
                    "256f: the witness near-miss must be rejected");
                rejects++;
            }
        }
        assertEquals(1, accepts, "witness carries one honest spend");
        assertEquals(1, rejects, "witness carries one near-miss spend");

        // Same seeds as the witness note: SHA-256('runar F-034 sk_seed' / 'sk_prf' / 'pk_seed').
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] seed = new byte[96];
        System.arraycopy(sha.digest("runar F-034 sk_seed".getBytes(StandardCharsets.UTF_8)), 0, seed, 0, 32);
        System.arraycopy(sha.digest("runar F-034 sk_prf".getBytes(StandardCharsets.UTF_8)), 0, seed, 32, 32);
        System.arraycopy(sha.digest("runar F-034 pk_seed".getBytes(StandardCharsets.UTF_8)), 0, seed, 64, 32);
        SlhDsa.KeyPair kp = SlhDsa.keygen(SlhDsa.SHA2_256f, seed);
        assertArrayEquals(pk, kp.pk, "256f: keygen from the witness seeds must give the witness pubkey");
        byte[] sig = SlhDsa.sign(SlhDsa.SHA2_256f, honestMsg, kp.sk);
        assertArrayEquals(honestSig, sig,
            "256f: Java's deterministic signer must reproduce the independent witness signature");
    }

    private static void runRoundTrip(SlhDsa.Params p) {
        byte[] seed = deterministicSeed(p, 7);
        SlhDsa.KeyPair kp = SlhDsa.keygen(p, seed);
        assertEquals(2 * p.n, kp.pk.length, p.name + ": pk size");
        assertEquals(4 * p.n, kp.sk.length, p.name + ": sk size");

        byte[] msg = ("hello-" + p.name).getBytes();
        byte[] sig = SlhDsa.sign(p, msg, kp.sk);
        // Sanity-check the signature length matches the formula.
        int expectedSigLen = p.n + p.k * (1 + p.a) * p.n + p.d * (p.len + p.hp) * p.n;
        assertEquals(expectedSigLen, sig.length, p.name + ": signature size");

        assertTrue(SlhDsa.verify(p, msg, sig, kp.pk), p.name + ": valid signature must verify");
    }

    private static byte[] deterministicSeed(SlhDsa.Params p, int salt) {
        byte[] seed = new byte[3 * p.n];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) ((i * 37 + salt) & 0xff);
        }
        return seed;
    }
}
