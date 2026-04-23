package runar.compiler.ir.stack;

import java.math.BigInteger;

/**
 * Constructor-argument placeholder inserted at lock-script build time.
 * The deployment SDK splices in the actual constructor arg at the byte
 * offset recorded in the compiled artifact's {@code constructorSlots}.
 */
public record PlaceholderOp(
    BigInteger paramIndex,
    String paramName,
    StackSourceLoc sourceLoc
) implements StackOp {
    public PlaceholderOp(BigInteger paramIndex, String paramName) {
        this(paramIndex, paramName, null);
    }

    public PlaceholderOp(long paramIndex, String paramName) {
        this(BigInteger.valueOf(paramIndex), paramName, null);
    }

    @Override
    public String op() {
        return "placeholder";
    }
}
