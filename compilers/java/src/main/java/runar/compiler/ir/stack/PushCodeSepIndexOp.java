package runar.compiler.ir.stack;

/**
 * Push the index of the most-recent OP_CODESEPARATOR in the executing
 * script; filled in by the emitter after final script layout.
 */
public record PushCodeSepIndexOp(StackSourceLoc sourceLoc) implements StackOp {
    public PushCodeSepIndexOp() {
        this(null);
    }

    @Override
    public String op() {
        return "push_codesep_index";
    }
}
