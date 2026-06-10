package runar.lang.analyzer;

/**
 * A parsed opcode (or synthetic raw-span step) in source order. The
 * analyzer operates on a flat list of these.
 *
 * <p>{@code opcode} is the raw byte value (0..255) for real opcodes, or
 * {@code -1} for the synthetic RAW_SPAN step (spec §6 / §12). {@code name}
 * is the canonical opcode name per spec §4.
 *
 * <p>{@code pushEncoding} classifies push operations; one of
 * {@code "direct"}, {@code "pushdata1"}, {@code "pushdata2"},
 * {@code "pushdata4"}, {@code "opN"}, or {@code null} for non-pushes.
 *
 * <p>{@code dataLength} is the push payload length (0 for non-pushes /
 * opN; equals the declared length for pushdataN, possibly truncated).
 *
 * <p>{@code rawSpanIn}/{@code rawSpanOut} are the static stack effect
 * declared for a RAW_SPAN step; ignored for real opcodes.
 */
final class OpStep {
    final int offset;
    final int opcode; // raw byte 0..255, or -1 for RAW_SPAN
    final String name;
    final int size; // total byte length consumed by this step
    final String pushEncoding;
    final int dataLength;
    final int rawSpanIn;
    final int rawSpanOut;

    OpStep(int offset, int opcode, String name, int size,
           String pushEncoding, int dataLength, int rawSpanIn, int rawSpanOut) {
        this.offset = offset;
        this.opcode = opcode;
        this.name = name;
        this.size = size;
        this.pushEncoding = pushEncoding;
        this.dataLength = dataLength;
        this.rawSpanIn = rawSpanIn;
        this.rawSpanOut = rawSpanOut;
    }

    static OpStep op(int offset, int opcode, String name, int size) {
        return new OpStep(offset, opcode, name, size, null, 0, 0, 0);
    }

    static OpStep push(int offset, int opcode, String name, int size,
                       String pushEncoding, int dataLength) {
        return new OpStep(offset, opcode, name, size, pushEncoding, dataLength, 0, 0);
    }

    static OpStep rawSpan(int offset, int length, int inArity, int outArity) {
        return new OpStep(offset, -1, "RAW_SPAN", length, null, 0, inArity, outArity);
    }
}
