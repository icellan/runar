package runar.compiler.ir.stack;

import java.math.BigInteger;

public record BigIntPushValue(BigInteger value) implements PushValue {
    /**
     * Canonical Stack-IR JSON encoding. Mirrors
     * {@link runar.compiler.ir.anf.BigIntConst#raw()}: bare JSON integer
     * for JS-safe values, quoted decimal-string with the {@code n}
     * BigInt suffix for oversize bigints (e.g. 256-bit constants).
     */
    @Override
    public Object raw() {
        if (value.compareTo(JS_MIN_SAFE_INTEGER) >= 0
            && value.compareTo(JS_MAX_SAFE_INTEGER) <= 0) {
            return value;
        }
        return value.toString(10) + "n";
    }

    // Number.MAX_SAFE_INTEGER == 2^53 - 1 == 9007199254740991
    private static final BigInteger JS_MAX_SAFE_INTEGER =
        BigInteger.valueOf(9007199254740991L);
    private static final BigInteger JS_MIN_SAFE_INTEGER =
        BigInteger.valueOf(-9007199254740991L);
}
