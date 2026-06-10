package runar.lang.analyzer;

/**
 * A raw-script span produced by a {@code raw_script} ANF node. Per
 * spec §12, spans collapse runs of opcodes into a single synthetic
 * step with declared stack effect {@code (inArity, outArity)}.
 */
public final class RawScriptSpan {
    public final int offset;
    public final int length;
    public final int inArity;
    public final int outArity;

    public RawScriptSpan(int offset, int length, int inArity, int outArity) {
        this.offset = offset;
        this.length = length;
        this.inArity = inArity;
        this.outArity = outArity;
    }
}
