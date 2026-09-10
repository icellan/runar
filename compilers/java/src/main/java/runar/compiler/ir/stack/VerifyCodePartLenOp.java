package runar.compiler.ir.stack;

/**
 * R-095 — pin {@code SIZE(_codePart)} against the code part's own DEPLOYED
 * byte length.
 *
 * <p>Consumes nothing: expects the numeric {@code SIZE(_codePart)} on top of
 * the stack and leaves it there, aborting via OP_VERIFY when the claimed code
 * part is not the length the deployed script actually has.
 *
 * <p>The length is not known when the stack lowerer runs (byte offsets only
 * exist after {@code Emit}), so the emitter resolves it: it reserves a
 * FIXED-WIDTH 9-byte sequence
 *
 * <pre>OP_DUP &lt;04 LL LL LL LL&gt; OP_BIN2NUM (OP_NUMEQUAL|OP_GREATERTHANOREQUAL) OP_VERIFY</pre>
 *
 * and back-patches {@code LL LL LL LL} (little-endian) once the whole script
 * has been emitted. The width is fixed so that the patched value can never
 * change the length it is describing — a minimal script-number push would be
 * self-referential.
 *
 * <p>{@code delta} is the deploy-time byte GROWTH of the template's OP_0
 * placeholders, so {@code deployedCodeLen = emittedTemplateLen + delta}.
 * {@code exact} says whether every placeholder's growth is type-determined:
 *
 * <ul>
 *   <li>{@code exact == true}  &rarr; {@code SIZE(_codePart) == emittedLen + delta}
 *       (OP_NUMEQUAL).</li>
 *   <li>{@code exact == false} &rarr; {@code SIZE(_codePart) >= emittedLen + delta}
 *       (OP_GREATERTHANOREQUAL). A variable-width readonly constructor argument
 *       ({@code bigint}, {@code ByteString}) has no compile-time width, and
 *       placeholder growth is never negative, so the sum is still a sound LOWER
 *       bound.</li>
 * </ul>
 *
 * <p>Unlike every other Stack IR variant this is a mutable class rather than a
 * record: {@code delta} / {@code exact} are only knowable once EVERY method has
 * been lowered (a constructor slot exists only where a property is actually
 * loaded), so {@code StackLower#pinCodePartLength} resolves them in place after
 * the fact — matching the TS / Go references, which mutate the same op object.
 */
public final class VerifyCodePartLenOp implements StackOp {

    /** Deploy-time byte growth of the template's OP_0 placeholders. */
    private int delta;

    /** true &rarr; exact equality pin; false &rarr; lower-bound pin. */
    private boolean exact;

    private StackSourceLoc sourceLoc;

    public VerifyCodePartLenOp() {
        this(0, false, null);
    }

    public VerifyCodePartLenOp(int delta, boolean exact) {
        this(delta, exact, null);
    }

    public VerifyCodePartLenOp(int delta, boolean exact, StackSourceLoc sourceLoc) {
        this.delta = delta;
        this.exact = exact;
        this.sourceLoc = sourceLoc;
    }

    public int delta() {
        return delta;
    }

    public boolean exact() {
        return exact;
    }

    public StackSourceLoc sourceLoc() {
        return sourceLoc;
    }

    /** Resolved by {@code StackLower#pinCodePartLength} after every method is lowered. */
    public void resolve(int delta, boolean exact) {
        this.delta = delta;
        this.exact = exact;
    }

    /** Stamped by the lowering context, mirroring the TS tier's in-place stamp. */
    public void setSourceLoc(StackSourceLoc loc) {
        this.sourceLoc = loc;
    }

    @Override
    public String op() {
        return "verify_code_part_len";
    }
}
