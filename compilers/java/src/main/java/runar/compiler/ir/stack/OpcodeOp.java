package runar.compiler.ir.stack;

/**
 * Emit a raw Bitcoin Script opcode (e.g. {@code "OP_ADD"},
 * {@code "OP_CHECKSIG"}).
 */
public record OpcodeOp(String code, StackSourceLoc sourceLoc) implements StackOp {
    public OpcodeOp(String code) {
        this(code, null);
    }

    @Override
    public String op() {
        return "opcode";
    }
}
