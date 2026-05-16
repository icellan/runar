package runar.compiler.ir.stack;

/**
 * Opaque opcode-byte span emitted verbatim by a {@code raw_script} ANF
 * node. The bytes are never inspected — the peephole optimizer treats
 * this op as a hard barrier and the emit pass writes the bytes verbatim,
 * recording a {@code RawScriptSpan} so the static analyzer can treat the
 * span as one opaque stack-effect step.
 *
 * <p>Stack effect is declared via {@link #inArity()} / {@link #outArity()};
 * the stack lowerer pops {@code inArity} items and pushes {@code outArity}
 * named slots so downstream PICK/ROLL/DROP refer to the correct slot.
 */
public record RawBytesOp(byte[] bytes, int inArity, int outArity) implements StackOp {
    @Override
    public String op() {
        return "raw_bytes";
    }
}
