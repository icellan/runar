package runar.integration.helpers;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Rabin signing helpers for integration tests. Mirrors
 * {@code integration/python/conftest.py::rabin_sign} and the Ruby /
 * Go equivalents so the same demo keypair signs the same price the
 * same way across every language tier.
 *
 * <p>Uses 130-bit demo primes — adequate for unit tests; production
 * deployments must use 1024+ bit primes.
 */
public final class RabinHelpers {

    public static final BigInteger P = new BigInteger("1361129467683753853853498429727072846227");
    public static final BigInteger Q = new BigInteger("1361129467683753853853498429727082846007");
    public static final BigInteger N = P.multiply(Q);

    private RabinHelpers() {}

    public static record Signature(BigInteger sig, BigInteger padding) {}

    /** Rabin-sign {@code msg} with the demo keypair. */
    public static Signature sign(byte[] msg) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(msg);
            BigInteger hashBn = bytesToUnsignedLE(h);

            for (int padding = 0; padding < 1000; padding++) {
                BigInteger pad = BigInteger.valueOf(padding);
                BigInteger target = hashBn.subtract(pad).mod(N);
                if (!isQR(target, P) || !isQR(target, Q)) continue;
                BigInteger sp = target.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
                BigInteger sq = target.modPow(Q.add(BigInteger.ONE).shiftRight(2), Q);
                BigInteger sig = crt(sp, P, sq, Q);
                if (sig.multiply(sig).add(pad).mod(N).equals(hashBn.mod(N))) {
                    return new Signature(sig, pad);
                }
                BigInteger sigAlt = N.subtract(sig);
                if (sigAlt.multiply(sigAlt).add(pad).mod(N).equals(hashBn.mod(N))) {
                    return new Signature(sigAlt, pad);
                }
            }
            throw new RuntimeException("RabinHelpers.sign: no valid padding found");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** {@code num2bin(value, length)} — encode unsigned LE into {@code length} bytes. */
    public static byte[] num2binLE(long value, int length) {
        byte[] out = new byte[length];
        long v = value;
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return out;
    }

    /** Convert a non-negative integer to unsigned LE hex (matches Bitcoin Script). */
    public static String toUnsignedLEHex(BigInteger n) {
        if (n.signum() == 0) return "00";
        StringBuilder sb = new StringBuilder();
        BigInteger v = n;
        BigInteger b256 = BigInteger.valueOf(256);
        while (v.signum() > 0) {
            BigInteger[] dr = v.divideAndRemainder(b256);
            sb.append(String.format("%02x", dr[1].intValue()));
            v = dr[0];
        }
        return sb.toString();
    }

    private static BigInteger bytesToUnsignedLE(byte[] buf) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < buf.length; i++) {
            result = result.add(BigInteger.valueOf(buf[i] & 0xff).shiftLeft(i * 8));
        }
        return result;
    }

    private static boolean isQR(BigInteger a, BigInteger p) {
        if (a.mod(p).signum() == 0) return true;
        return a.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE);
    }

    private static BigInteger crt(BigInteger a1, BigInteger m1, BigInteger a2, BigInteger m2) {
        BigInteger m = m1.multiply(m2);
        BigInteger p1 = m2.modPow(m1.subtract(BigInteger.TWO), m1);
        BigInteger p2 = m1.modPow(m2.subtract(BigInteger.TWO), m2);
        return a1.multiply(m2).multiply(p1).add(a2.multiply(m1).multiply(p2)).mod(m);
    }
}
