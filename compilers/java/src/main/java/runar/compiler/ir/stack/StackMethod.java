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
 */
public record StackMethod(String name, List<StackOp> ops, BigInteger maxStackDepth) {
    public StackMethod(String name, List<StackOp> ops, long maxStackDepth) {
        this(name, ops, BigInteger.valueOf(maxStackDepth));
    }
}
