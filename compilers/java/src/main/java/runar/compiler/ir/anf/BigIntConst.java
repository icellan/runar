package runar.compiler.ir.anf;

import java.math.BigInteger;

public record BigIntConst(BigInteger value) implements ConstValue {
    /**
     * Canonical IR JSON encoding. Values that fit in JS
     * {@code Number.MIN_SAFE_INTEGER..MAX_SAFE_INTEGER} round-trip as a
     * bare JSON integer (matching TS / Go / Python). Oversize bigints —
     * e.g. the 256-bit {@code EC_N} group order used by schnorr-zkp —
     * lose precision through a JSON number and must instead be encoded
     * as a quoted decimal string with the canonical JS BigInt {@code n}
     * suffix. The trailing {@code n} is the discriminator that lets the
     * Go / Python / Java loaders distinguish a decimal-encoded BigInt
     * from a hex-encoded ByteString literal (which never carries the
     * suffix), so {@code "3030"} stays a 2-byte bytestring and
     * {@code "3030n"} decodes as the integer 3030.
     */
    @Override
    public Object raw() {
        if (isJsSafeInteger(value)) {
            return value;
        }
        return value.toString(10) + "n";
    }

    static boolean isJsSafeInteger(BigInteger v) {
        return v.compareTo(JS_MIN_SAFE_INTEGER) >= 0
            && v.compareTo(JS_MAX_SAFE_INTEGER) <= 0;
    }

    // Number.MAX_SAFE_INTEGER == 2^53 - 1 == 9007199254740991
    private static final BigInteger JS_MAX_SAFE_INTEGER =
        BigInteger.valueOf(9007199254740991L);
    private static final BigInteger JS_MIN_SAFE_INTEGER =
        BigInteger.valueOf(-9007199254740991L);
}
