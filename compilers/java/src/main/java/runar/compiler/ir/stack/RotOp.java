package runar.compiler.ir.stack;

public record RotOp(StackSourceLoc sourceLoc) implements StackOp {
    public RotOp() {
        this(null);
    }

    @Override
    public String op() {
        return "rot";
    }
}
