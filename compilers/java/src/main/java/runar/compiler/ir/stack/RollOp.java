package runar.compiler.ir.stack;

import java.math.BigInteger;

/**
 * {@code depth} is a {@link BigInteger} so that
 * {@link runar.compiler.canonical.Jcs} emits it as a bare JSON integer
 * (Jcs throws on {@code Integer}/{@code Long}).
 */
public record RollOp(BigInteger depth, StackSourceLoc sourceLoc) implements StackOp {
    public RollOp(BigInteger depth) {
        this(depth, null);
    }

    public RollOp(long depth) {
        this(BigInteger.valueOf(depth), null);
    }

    @Override
    public String op() {
        return "roll";
    }
}
