package runar.compiler.ir.stack;

public record SwapOp(StackSourceLoc sourceLoc) implements StackOp {
    public SwapOp() {
        this(null);
    }

    @Override
    public String op() {
        return "swap";
    }
}
