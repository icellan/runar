package runar.compiler.ir.stack;

public record NipOp(StackSourceLoc sourceLoc) implements StackOp {
    public NipOp() {
        this(null);
    }

    @Override
    public String op() {
        return "nip";
    }
}
