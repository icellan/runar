package runar.lang.analyzer;

import java.util.ArrayList;
import java.util.List;

/** Signature-hygiene findings (spec §9). */
final class SigAnalyzer {
    private SigAnalyzer() {}

    static List<Finding> analyze(List<OpStep> ops, List<ExecutionPath> paths) {
        List<Finding> out = new ArrayList<>();
        // NO_SIG_CHECK: one finding per reachable path lacking CHECKSIG/MULTISIG.
        for (ExecutionPath p : paths) {
            if (!p.reachable) continue;
            if (p.hasCheckSig) continue;
            out.add(new Finding(
                "warning", "NO_SIG_CHECK",
                "Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)",
                null, null, p.description));
        }
        // CHECKSIG_RESULT_DROPPED: walk linearly, flag CHECKSIG/MULTISIG
        // followed immediately by OP_DROP.
        for (int i = 0; i + 1 < ops.size(); i++) {
            OpStep a = ops.get(i);
            OpStep b = ops.get(i + 1);
            if ((a.opcode == Opcodes.OP_CHECKSIG || a.opcode == Opcodes.OP_CHECKMULTISIG)
                && b.opcode == Opcodes.OP_DROP) {
                out.add(new Finding(
                    "warning", "CHECKSIG_RESULT_DROPPED",
                    a.name + " result is dropped by " + b.name
                        + " — signature check has no effect",
                    a.offset, a.name, null));
            }
        }
        return out;
    }
}
