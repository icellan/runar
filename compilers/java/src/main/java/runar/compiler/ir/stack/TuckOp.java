package runar.compiler.ir.stack;

public record TuckOp(StackSourceLoc sourceLoc) implements StackOp {
    public TuckOp() {
        this(null);
    }

    @Override
    public String op() {
        return "tuck";
    }
}
