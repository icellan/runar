package runar.lang.runtime;

import java.math.BigInteger;
import java.security.MessageDigest;

import org.junit.jupiter.api.Test;

import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the off-chain Rabin verifier's padding bound
 * ({@link MockCrypto#verifyRabinSig}). Mirrors the Go reference test
 * ({@code packages/runar-go/rabin_padding_bound_test.go}).
 *
 * <p>The on-chain Rabin script enforces {@code 0 <= padding < 65536} via
 * OP_WITHIN. Without the same bound off-chain, the verifier accepts a
 * universal forgery the deployed script rejects: with {@code sig = 0} and
 * {@code padding = SHA256(msg)}, {@code (0^2 + SHA256(msg)) mod n} equals
 * {@code SHA256(msg) mod n} for every message.
 */
class RabinPaddingBoundTest {

    // Rabin test primes, both ≡ 3 (mod 4) so square roots are computable via
    // a^((p+1)/4) mod p — keeps the honest signer self-contained in the test.
    private static final BigInteger P = new BigInteger("1361129467683753853853498429727072846227");
    private static final BigInteger Q = new BigInteger("1361129467683753853853498429727082846007");
    private static final BigInteger N = P.multiply(Q);

    @Test
    void rejectsUniversalForgery() {
        byte[] msg = "attack at dawn".getBytes();

        // padding = SHA256(msg) as raw bytes — its little-endian value is
        // >= 65536, so the bound must reject it.
        byte[] forgedPadding = sha256(msg);

        boolean accepted = MockCrypto.verifyRabinSig(
                new ByteString(msg),
                BigInteger.ZERO,            // sig = 0
                new ByteString(forgedPadding),
                N);

        assertFalse(accepted,
                "forgery accepted: sig=0, padding=SHA256(msg) must be rejected by the padding bound");
    }

    @Test
    void acceptsHonestSignature() {
        byte[] msg = "attack at dawn".getBytes();

        BigInteger[] sigAndPad = sign(msg);
        BigInteger sig = sigAndPad[0];
        BigInteger pad = sigAndPad[1];

        // padding < 65536, encoded little-endian as the verifier expects.
        byte[] padBytes = unsignedToLE(pad);

        boolean accepted = MockCrypto.verifyRabinSig(
                new ByteString(msg),
                sig,
                new ByteString(padBytes),
                N);

        assertTrue(accepted, "honest signature rejected: sig=" + sig + " padding=" + pad);
    }

    /**
     * N-380 (F-368 follow-up): the script asserts {@code sig < n}, so
     * {@code sig + k*n} aborts on chain. Proves: the canonical sig and the
     * second root {@code n - sig} verify; {@code sig + n} and {@code sig + 2n}
     * are rejected. Does not prove the verdict equals the consensus
     * interpreter's (conformance/negatives/f368 does that).
     */
    @Test
    void rejectsNonCanonicalSigAtOrAboveModulus() {
        byte[] msg = "attack at dawn".getBytes();
        BigInteger[] sigAndPad = sign(msg);
        BigInteger sig = sigAndPad[0];
        ByteString pad = new ByteString(unsignedToLE(sigAndPad[1]));
        ByteString m = new ByteString(msg);

        assertTrue(MockCrypto.verifyRabinSig(m, sig, pad, N), "canonical sig rejected");
        assertTrue(MockCrypto.verifyRabinSig(m, N.subtract(sig), pad, N), "second root n - sig rejected");
        assertFalse(MockCrypto.verifyRabinSig(m, sig.add(N), pad, N), "sig + n accepted");
        assertFalse(MockCrypto.verifyRabinSig(m, sig.add(N.shiftLeft(1)), pad, N), "sig + 2n accepted");
    }

    // --- honest signer (test-only) -------------------------------------

    /** Returns {sig, padding} with padding < 65536 such that (sig^2 + padding) mod n == H(msg) mod n. */
    private static BigInteger[] sign(byte[] msg) {
        BigInteger hashBN = leToUnsigned(sha256(msg));
        BigInteger hashModN = hashBN.mod(N);

        for (long pad = 0; pad < 65536; pad++) {
            BigInteger padBig = BigInteger.valueOf(pad);
            BigInteger target = hashModN.subtract(padBig).mod(N);
            BigInteger root = sqrtModPQ(target);
            if (root != null) {
                BigInteger check = root.multiply(root).add(padBig).mod(N);
                if (check.equals(hashModN)) {
                    return new BigInteger[]{root, padBig};
                }
            }
        }
        throw new IllegalStateException("no valid padding < 65536 found for test message");
    }

    /** sqrt of a mod n=p*q via CRT, or null if not a quadratic residue. */
    private static BigInteger sqrtModPQ(BigInteger a) {
        BigInteger rp = sqrtMod3(a, P);
        if (rp == null) return null;
        BigInteger rq = sqrtMod3(a, Q);
        if (rq == null) return null;
        BigInteger qInvP = Q.modInverse(P);
        BigInteger pInvQ = P.modInverse(Q);
        BigInteger t1 = rp.multiply(Q).multiply(qInvP);
        BigInteger t2 = rq.multiply(P).multiply(pInvQ);
        return t1.add(t2).mod(N);
    }

    /** sqrt of a mod prime p where p ≡ 3 (mod 4); null if a is not a QR. */
    private static BigInteger sqrtMod3(BigInteger a, BigInteger p) {
        a = a.mod(p);
        if (a.signum() == 0) return BigInteger.ZERO;
        BigInteger r = a.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        return r.multiply(r).mod(p).equals(a) ? r : null;
    }

    // --- byte helpers ---------------------------------------------------

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Unsigned little-endian bytes to BigInteger. */
    private static BigInteger leToUnsigned(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[le.length - 1 - i] = le[i];
        return new BigInteger(1, be);
    }

    /** BigInteger to minimal unsigned little-endian bytes. */
    private static byte[] unsignedToLE(BigInteger n) {
        if (n.signum() == 0) return new byte[]{0};
        byte[] be = n.toByteArray();           // big-endian, may have leading 0x00 sign byte
        int start = (be.length > 1 && be[0] == 0) ? 1 : 0;
        int len = be.length - start;
        byte[] le = new byte[len];
        for (int i = 0; i < len; i++) le[i] = be[be.length - 1 - i];
        return le;
    }
}
