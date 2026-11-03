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
 *
 * <p>F-316 — {@code sourceLoc} mirrors the TS reference's {@code
 * RawBytesOp} (packages/runar-compiler/src/ir/stack-ir.ts), which has
 * carried this field since its generic {@code emitOp} stamps every
 * emitted op including a raw_script span. Java previously had no field
 * here, so a located {@code asm({...})} statement produced no
 * source-map entry at all.
 */
public record RawBytesOp(byte[] bytes, int inArity, int outArity, StackSourceLoc sourceLoc) implements StackOp {
    public RawBytesOp(byte[] bytes, int inArity, int outArity) {
        this(bytes, inArity, outArity, null);
    }

    @Override
    public String op() {
        return "raw_bytes";
    }
}
