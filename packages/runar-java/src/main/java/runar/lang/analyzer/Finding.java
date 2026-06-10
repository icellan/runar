package runar.lang.analyzer;

import java.util.Objects;

/**
 * Single analyzer finding. Optional fields are {@code null}/absent when
 * not applicable — the JSON emitter omits them per spec §3.2.
 *
 * <p>{@code insertionOrder} is sidecar metadata used to break ties when
 * {@link Analyzer} stably sorts findings by (severity, offset); it is
 * never emitted.
 */
public final class Finding {
    public final String severity; // "error" | "warning" | "info"
    public final String code;
    public final String message;
    public final Integer offset; // null = absent
    public final String opcode; // null = absent
    public final String path; // null = absent

    int insertionOrder; // package-private; set by Analyzer before sort

    public Finding(String severity, String code, String message,
                   Integer offset, String opcode, String path) {
        this.severity = Objects.requireNonNull(severity);
        this.code = Objects.requireNonNull(code);
        this.message = Objects.requireNonNull(message);
        this.offset = offset;
        this.opcode = opcode;
        this.path = path;
    }

    public Finding withPath(String newPath) {
        return new Finding(severity, code, message, offset, opcode, newPath);
    }

    static int severityRank(String s) {
        return switch (s) {
            case "error" -> 0;
            case "warning" -> 1;
            case "info" -> 2;
            default -> 3;
        };
    }
}
