package runar.compiler.ir.stack;

public record OverOp(StackSourceLoc sourceLoc) implements StackOp {
    public OverOp() {
        this(null);
    }

    @Override
    public String op() {
        return "over";
    }
}
