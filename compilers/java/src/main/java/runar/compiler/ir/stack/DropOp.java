package runar.compiler.ir.stack;

public record DropOp(StackSourceLoc sourceLoc) implements StackOp {
    public DropOp() {
        this(null);
    }

    @Override
    public String op() {
        return "drop";
    }
}
