package runar.lang.runtime;

import java.math.BigInteger;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GK-BUG-013 (off-chain half, Java tier): {@code MockCrypto.sha256Finalize} must
 * refuse a msgBitLen outside [0, 2^64), the domain the compiled script enforces
 * with its {@code <00> OP_EQUALVERIFY} sign-byte check.
 *
 * <p>It used to call {@code msgBitLen.longValueExact()} and write the two's
 * complement: -24 produced the 2^64 - 24 length field (a digest no script
 * computes), 2^64 + 24 threw an unrelated {@link ArithmeticException}, and so
 * did every length in [2^63, 2^64) — which the script ACCEPTS.
 *
 * <p>Proves: -24, -1, 2^64 and 2^64 + 24 throw {@link IllegalArgumentException}
 * naming the domain and the value; 24 still yields the JDK's SHA-256("abc");
 * 2^63 + 24 and 2^64 - 8 (the upper half of the domain) are accepted and equal
 * a one-block FIPS 180-4 reference built on {@code sha256Compress}, itself
 * anchored to the JDK digest.
 * Does not prove: the other six tiers (each has its own gk-bug-013 test).
 */
class GkBug013Sha256FinalizeTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);

    private static ByteString finalizeAbc(BigInteger bitLen) {
        return MockCrypto.sha256Finalize(
            new ByteString(MockCrypto.SHA256_IV), new ByteString("abc".getBytes()), bitLen);
    }

    /** One 64-byte block: "abc" || 0x80 || zeros || 8-byte big-endian length field. */
    private static String refOneBlock(BigInteger lengthField) {
        byte[] block = new byte[64];
        block[0] = 'a';
        block[1] = 'b';
        block[2] = 'c';
        block[3] = (byte) 0x80;
        byte[] len = lengthField.toByteArray();
        for (int i = 0; i < 8 && i < len.length; i++) {
            block[63 - i] = len[len.length - 1 - i];
        }
        return MockCrypto.sha256Compress(new ByteString(MockCrypto.SHA256_IV), new ByteString(block)).toHex();
    }

    @Test
    void referenceIsAnchoredToTheJdkDigest() {
        assertEquals(HEX.formatHex(MockCrypto.sha256("abc".getBytes())), refOneBlock(BigInteger.valueOf(24)));
    }

    @Test
    void honestLengthStillHashes() {
        assertEquals(HEX.formatHex(MockCrypto.sha256("abc".getBytes())), finalizeAbc(BigInteger.valueOf(24)).toHex());
    }

    @Test
    void refusesBitLenOutsideTheDomain() {
        for (BigInteger bitLen : new BigInteger[] {
            BigInteger.valueOf(-24), BigInteger.valueOf(-1), TWO_64, TWO_64.add(BigInteger.valueOf(24)),
        }) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> finalizeAbc(bitLen),
                "sha256Finalize(IV, abc, " + bitLen + ") must refuse");
            assertTrue(e.getMessage().contains("msgBitLen must be in [0, 2^64), got " + bitLen),
                "diagnostic was: " + e.getMessage());
        }
    }

    @Test
    void acceptsTheUpperHalfOfTheDomain() {
        for (BigInteger bitLen : new BigInteger[] {
            BigInteger.ONE.shiftLeft(63).add(BigInteger.valueOf(24)), TWO_64.subtract(BigInteger.valueOf(8)),
        }) {
            assertEquals(refOneBlock(bitLen), finalizeAbc(bitLen).toHex(), "length " + bitLen);
        }
    }
}
