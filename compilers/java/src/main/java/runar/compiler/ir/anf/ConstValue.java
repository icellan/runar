package runar.compiler.ir.anf;

import java.math.BigInteger;

/**
 * The constant payload of a {@link LoadConst} binding.
 *
 * <p>Mirrors the TypeScript union {@code string | bigint | boolean}
 * used in {@code ANFProperty.initialValue} and {@code LoadConst.value}.
 * Canonical JSON emits {@code BigIntConst} as a bare integer,
 * {@code BytesConst} as a string, {@code BoolConst} as a JSON boolean.
 */
public sealed interface ConstValue permits BigIntConst, BoolConst, BytesConst {
    /** The raw value to be serialised (BigInteger, Boolean, or String). */
    Object raw();

    static ConstValue of(BigInteger v) {
        return new BigIntConst(v);
    }

    static ConstValue of(long v) {
        return new BigIntConst(BigInteger.valueOf(v));
    }

    static ConstValue of(boolean v) {
        return new BoolConst(v);
    }

    static ConstValue ofHex(String hex) {
        return new BytesConst(hex);
    }
}
