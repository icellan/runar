package runar.compiler.ir.stack;

import java.math.BigInteger;

/**
 * Optional source-location annotation for a {@link StackOp}. Used for
 * debug source maps; canonical JSON omits {@code sourceLoc} components
 * that are {@code null} (via {@link runar.compiler.canonical.Jcs}'s
 * null-component elision), so this is not part of the conformance
 * boundary.
 *
 * <p>Matches {@code StackSourceLoc} in
 * {@code packages/runar-ir-schema/src/stack-ir.ts}. {@code line} and
 * {@code column} are {@link BigInteger} so that canonical JSON emits
 * them as bare integers.
 */
public record StackSourceLoc(String file, BigInteger line, BigInteger column) {
    public StackSourceLoc(String file, long line, long column) {
        this(file, BigInteger.valueOf(line), BigInteger.valueOf(column));
    }
}
