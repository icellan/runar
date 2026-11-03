package runar.lang.analyzer;

import java.util.ArrayList;
import java.util.List;

/** Misc opcode concerns: CODESEPARATOR, LARGE_SCRIPT (spec §10). */
final class OpcodeConcerns {
    private OpcodeConcerns() {}

    static final int LARGE_SCRIPT_THRESHOLD = 500_000;

    static List<Finding> analyze(List<OpStep> ops, int scriptSizeBytes) {
        List<Finding> out = new ArrayList<>();
        if (scriptSizeBytes > LARGE_SCRIPT_THRESHOLD) {
            String kb = jsToFixed1((double) scriptSizeBytes / 1024.0);
            out.add(new Finding(
                "info", "LARGE_SCRIPT",
                "Script is " + scriptSizeBytes + " bytes (" + kb
                    + " KB) — consider if this is intentional",
                null, null, null));
        }
        for (OpStep op : ops) {
            if (op.opcode == Opcodes.OP_CODESEPARATOR) {
                out.add(new Finding(
                    "info", "CODESEPARATOR_PRESENT",
                    "OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise",
                    op.offset, op.name, null));
            }
        }
        return out;
    }

    /**
     * Match JS {@code Number.prototype.toFixed(1)} semantics. Per ECMA-262,
     * {@code toFixed} picks the integer {@code n} for which
     * {@code n / 10 - value} is closest to zero; if two values of
     * {@code n} are equally close (an exact tie), it picks the LARGER one.
     * That is round-half-up (ties away from zero for our non-negative
     * inputs), not IEEE-754 round-half-to-even — verified live:
     * {@code node -e "console.log((500992/1024).toFixed(1))"} prints
     * {@code "489.3"}, where round-half-to-even would give {@code "489.2"}.
     * {@code value} here is always {@code scriptSizeBytes / 1024}, which is
     * exact in a double (1024 is a power of two), so the tie can only come
     * from the decimal rounding step itself, which {@link Math#round} — a
     * {@code floor(x + 0.5)} ties-toward-+Infinity rounding — reproduces
     * exactly for non-negative {@code x}.
     */
    static String jsToFixed1(double value) {
        double scaled = value * 10.0;
        long rounded = Math.round(scaled);
        long intPart;
        long fracPart;
        if (rounded < 0) {
            long abs = -rounded;
            intPart = -(abs / 10);
            fracPart = abs % 10;
            return intPart + "." + fracPart;
        }
        intPart = rounded / 10;
        fracPart = rounded % 10;
        return intPart + "." + fracPart;
    }
}
