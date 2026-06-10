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
     * Match JS {@code Number.prototype.toFixed(1)} semantics: round to one
     * decimal place using IEEE-754 banker's rounding (round-half-to-even).
     * Spec §5.1 canonical formula: {@code k = round_half_to_even(n * 10 / 1024) / 10}.
     */
    static String jsToFixed1(double value) {
        // Java's printf "%.1f" uses HALF_UP. We need HALF_EVEN. Use
        // Math.rint (round-half-to-even) on (value * 10) and divide.
        double scaled = value * 10.0;
        double rounded = Math.rint(scaled);
        long intPart;
        long fracPart;
        if (rounded < 0) {
            long abs = (long) (-rounded);
            intPart = -(abs / 10);
            fracPart = abs % 10;
            return intPart + "." + fracPart;
        }
        long abs = (long) rounded;
        intPart = abs / 10;
        fracPart = abs % 10;
        return intPart + "." + fracPart;
    }
}
