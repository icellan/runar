package runar.compiler.ir.stack;

public record DupOp(StackSourceLoc sourceLoc) implements StackOp {
    public DupOp() {
        this(null);
    }

    @Override
    public String op() {
        return "dup";
    }
}
