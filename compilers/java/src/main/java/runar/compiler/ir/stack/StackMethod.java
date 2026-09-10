package runar.compiler.ir.stack;

import java.math.BigInteger;
import java.util.List;

/**
 * One method lowered to a flat sequence of stack operations.
 * {@code maxStackDepth} is a static upper bound on live-temporary depth
 * required to execute {@code ops}; it is a {@link BigInteger} so that
 * {@link runar.compiler.canonical.Jcs} emits it as a bare JSON integer.
 *
 * <p>Matches {@code StackMethod} in
 * {@code packages/runar-ir-schema/src/stack-ir.ts}.
 *
 * <p>{@code needsCodeSeparator} is true if this method's lowering needs the
 * script-level OP_CODESEPARATOR the emitter places at offset 1 of the locking
 * script (R-010). Contract-level: true for every method of a contract in which
 * ANY method authenticates a {@code _codePart} witness. It is a
 * compiler-internal marker with no Stack-IR schema counterpart, so it is
 * omitted from the canonical JSON when false (see
 * {@link runar.compiler.canonical.JsonOmitWhenFalse}).
 */
public record StackMethod(
    String name,
    List<StackOp> ops,
    BigInteger maxStackDepth,
    @runar.compiler.canonical.JsonOmitWhenFalse boolean needsCodeSeparator
) {
    public StackMethod(String name, List<StackOp> ops, BigInteger maxStackDepth) {
        this(name, ops, maxStackDepth, false);
    }

    public StackMethod(String name, List<StackOp> ops, long maxStackDepth) {
        this(name, ops, BigInteger.valueOf(maxStackDepth), false);
    }

    public StackMethod(String name, List<StackOp> ops, long maxStackDepth, boolean needsCodeSeparator) {
        this(name, ops, BigInteger.valueOf(maxStackDepth), needsCodeSeparator);
    }
}
