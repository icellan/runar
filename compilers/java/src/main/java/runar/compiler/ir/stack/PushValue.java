package runar.compiler.ir.stack;

import java.math.BigInteger;

/**
 * The payload of a {@link PushOp}.
 *
 * <p>Mirrors the TypeScript union {@code Uint8Array | bigint | boolean}
 * from {@code packages/runar-ir-schema/src/stack-ir.ts}.  Canonical JSON
 * emits {@link ByteStringPushValue} as a hex string, {@link BigIntPushValue}
 * as a bare integer, and {@link BoolPushValue} as a JSON boolean — via
 * {@link runar.compiler.canonical.Jcs}'s raw-value dispatch (parallel to
 * {@code ConstValue#raw()}).
 *
 * <p>Byte-string payloads are stored as hex-encoded {@link String}, not
 * raw {@code byte[]}, to keep the record deeply immutable and to match
 * how the rest of the compiler represents byte literals.
 */
public sealed interface PushValue permits ByteStringPushValue, BigIntPushValue, BoolPushValue {
    /** The raw value to be serialised (BigInteger, Boolean, or String). */
    Object raw();

    static PushValue of(BigInteger v) {
        return new BigIntPushValue(v);
    }

    static PushValue of(long v) {
        return new BigIntPushValue(BigInteger.valueOf(v));
    }

    static PushValue of(boolean v) {
        return new BoolPushValue(v);
    }

    static PushValue ofHex(String hex) {
        return new ByteStringPushValue(hex);
    }
}
