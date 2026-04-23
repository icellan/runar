package runar.compiler.ir.stack;

/**
 * Push a literal value onto the stack. {@code value} is one of
 * {@link ByteStringPushValue}, {@link BigIntPushValue}, or
 * {@link BoolPushValue} — {@link runar.compiler.canonical.Jcs}
 * unwraps the sealed interface via {@code raw()}.
 */
public record PushOp(PushValue value, StackSourceLoc sourceLoc) implements StackOp {
    public PushOp(PushValue value) {
        this(value, null);
    }

    @Override
    public String op() {
        return "push";
    }
}
