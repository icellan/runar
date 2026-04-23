package runar.compiler.ir.stack;

import java.math.BigInteger;

public record PickOp(BigInteger depth, StackSourceLoc sourceLoc) implements StackOp {
    public PickOp(BigInteger depth) {
        this(depth, null);
    }

    public PickOp(long depth) {
        this(BigInteger.valueOf(depth), null);
    }

    @Override
    public String op() {
        return "pick";
    }
}
