package runar.lang.analyzer;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses a normalized lowercase-hex Bitcoin Script into a list of
 * {@link OpStep}s. Implements spec §6 (push handling, truncated pushes,
 * {@code INEFFICIENT_PUSH} emission).
 *
 * <p>Truncated pushes are silently truncated with no extra finding (spec
 * §6.1). Inefficient encodings yield {@code INEFFICIENT_PUSH} findings
 * (spec §6.2).
 */
final class ScriptParser {
    private ScriptParser() {}

    /** Output of a parse — opcode list + any push-related findings. */
    static final class Parsed {
        final List<OpStep> opcodes;
        final List<Finding> findings;

        Parsed(List<OpStep> opcodes, List<Finding> findings) {
            this.opcodes = opcodes;
            this.findings = findings;
        }
    }

    static Parsed parse(String normalizedHex) {
        // hex → bytes (best-effort; assume the caller already normalized).
        int n = normalizedHex.length();
        if ((n & 1) != 0) {
            throw new AnalyzerException("hex script has odd length: " + n);
        }
        int byteLen = n / 2;
        byte[] bytes = new byte[byteLen];
        for (int i = 0; i < byteLen; i++) {
            int hi = hexDigit(normalizedHex.charAt(2 * i));
            int lo = hexDigit(normalizedHex.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) {
                throw new AnalyzerException(
                    "non-hex character at offset " + (2 * i) + " in script");
            }
            bytes[i] = (byte) ((hi << 4) | lo);
        }

        List<OpStep> ops = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        int i = 0;
        while (i < byteLen) {
            int b = bytes[i] & 0xff;
            int offset = i;
            if (b >= 0x01 && b <= 0x4b) {
                // direct push: b bytes of data follow
                int dataLen = b;
                int available = Math.min(dataLen, byteLen - (i + 1));
                int size = 1 + available;
                ops.add(OpStep.push(offset, b, "PUSH_" + dataLen, size,
                    "direct", dataLen));
                i += size;
                if (available < dataLen) {
                    // truncated — stop parsing (silent per §6.1).
                    return new Parsed(ops, findings);
                }
                continue;
            }
            if (b == Opcodes.OP_PUSHDATA1) {
                // 1-byte length follows
                if (i + 1 >= byteLen) {
                    ops.add(OpStep.push(offset, b, "OP_PUSHDATA1", byteLen - i,
                        "pushdata1", 0));
                    return new Parsed(ops, findings);
                }
                int dataLen = bytes[i + 1] & 0xff;
                int dataStart = i + 2;
                int available = Math.min(dataLen, byteLen - dataStart);
                int size = 2 + available;
                ops.add(OpStep.push(offset, b, "OP_PUSHDATA1", size,
                    "pushdata1", dataLen));
                if (dataLen <= 75) {
                    String hex = String.format("%02x", dataLen);
                    findings.add(new Finding(
                        "info", "INEFFICIENT_PUSH",
                        "OP_PUSHDATA1 used for " + dataLen
                            + "-byte data — direct push (opcode 0x" + hex
                            + ") would be more efficient",
                        offset, "OP_PUSHDATA1", null));
                }
                i += size;
                if (available < dataLen) {
                    return new Parsed(ops, findings);
                }
                continue;
            }
            if (b == Opcodes.OP_PUSHDATA2) {
                if (i + 2 >= byteLen) {
                    ops.add(OpStep.push(offset, b, "OP_PUSHDATA2", byteLen - i,
                        "pushdata2", 0));
                    return new Parsed(ops, findings);
                }
                int dataLen = (bytes[i + 1] & 0xff) | ((bytes[i + 2] & 0xff) << 8);
                int dataStart = i + 3;
                int available = Math.min(dataLen, byteLen - dataStart);
                int size = 3 + available;
                ops.add(OpStep.push(offset, b, "OP_PUSHDATA2", size,
                    "pushdata2", dataLen));
                if (dataLen <= 255) {
                    findings.add(new Finding(
                        "info", "INEFFICIENT_PUSH",
                        "OP_PUSHDATA2 used for " + dataLen
                            + "-byte data — OP_PUSHDATA1 would be more efficient",
                        offset, "OP_PUSHDATA2", null));
                }
                i += size;
                if (available < dataLen) {
                    return new Parsed(ops, findings);
                }
                continue;
            }
            if (b == Opcodes.OP_PUSHDATA4) {
                if (i + 4 >= byteLen) {
                    ops.add(OpStep.push(offset, b, "OP_PUSHDATA4", byteLen - i,
                        "pushdata4", 0));
                    return new Parsed(ops, findings);
                }
                long dataLenL =
                    ((long) (bytes[i + 1] & 0xff))
                        | (((long) (bytes[i + 2] & 0xff)) << 8)
                        | (((long) (bytes[i + 3] & 0xff)) << 16)
                        | (((long) (bytes[i + 4] & 0xff)) << 24);
                // Clamp to int range for further arithmetic; declared lengths
                // larger than the remaining script naturally truncate.
                int dataLen = (int) Math.min(dataLenL, (long) Integer.MAX_VALUE - 16);
                int dataStart = i + 5;
                int available = Math.min(dataLen, byteLen - dataStart);
                int size = 5 + available;
                ops.add(OpStep.push(offset, b, "OP_PUSHDATA4", size,
                    "pushdata4", dataLen));
                if (dataLen <= 65535) {
                    findings.add(new Finding(
                        "info", "INEFFICIENT_PUSH",
                        "OP_PUSHDATA4 used for " + dataLen
                            + "-byte data — OP_PUSHDATA2 would be more efficient",
                        offset, "OP_PUSHDATA4", null));
                }
                i += size;
                if (available < dataLen) {
                    return new Parsed(ops, findings);
                }
                continue;
            }
            // opN or other opcode
            String name = Opcodes.nameOf(b);
            if (name == null) {
                name = "OP_UNKNOWN(0x" + String.format("%02x", b) + ")";
            }
            // opN pushes (0x00, 0x4f, 0x51..0x60) are still single-byte opcodes
            // with no payload; OpStep.op covers them. pushEncoding stays null
            // since stack effects use the default (0,1) for any push.
            ops.add(OpStep.op(offset, b, name, 1));
            i++;
        }
        return new Parsed(ops, findings);
    }

    /** Collapse raw-script spans per spec §12. */
    static List<OpStep> collapseRawScriptSpans(List<OpStep> ops, List<RawScriptSpan> spans) {
        if (spans.isEmpty()) return ops;
        // Sort spans by offset (stable not required since offset is the sort key).
        List<RawScriptSpan> sorted = new ArrayList<>(spans);
        sorted.sort((a, b) -> Integer.compare(a.offset, b.offset));

        List<OpStep> out = new ArrayList<>();
        int spanIdx = 0;
        int lastSpanStartEmitted = -1;
        for (OpStep op : ops) {
            // Advance past spans whose end <= op.offset.
            while (spanIdx < sorted.size()
                && sorted.get(spanIdx).offset + sorted.get(spanIdx).length <= op.offset) {
                spanIdx++;
            }
            if (spanIdx >= sorted.size()) {
                out.add(op);
                continue;
            }
            RawScriptSpan span = sorted.get(spanIdx);
            int spanEnd = span.offset + span.length;
            if (op.offset + op.size <= span.offset) {
                out.add(op);
                continue;
            }
            if (op.offset >= span.offset && op.offset + op.size <= spanEnd) {
                // Entirely inside the span — drop and emit synthetic step if not already.
                if (lastSpanStartEmitted != span.offset) {
                    out.add(OpStep.rawSpan(span.offset, span.length,
                        span.inArity, span.outArity));
                    lastSpanStartEmitted = span.offset;
                }
                continue;
            }
            // Partial overlap (degenerate): drop, emit synthetic once.
            if (lastSpanStartEmitted != span.offset) {
                out.add(OpStep.rawSpan(span.offset, span.length,
                    span.inArity, span.outArity));
                lastSpanStartEmitted = span.offset;
            }
        }
        return out;
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
}
