package runar.lang.analyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Path enumeration + structural / per-path findings (spec §7).
 */
final class PathAnalyzer {
    private PathAnalyzer() {}

    static final int MAX_PATHS = 256;

    /** Output of the path analysis. */
    static final class PathResult {
        final List<ExecutionPath> paths;
        final List<Finding> findings;
        final boolean hasUnbalanced;

        PathResult(List<ExecutionPath> paths, List<Finding> findings,
                   boolean hasUnbalanced) {
            this.paths = paths;
            this.findings = findings;
            this.hasUnbalanced = hasUnbalanced;
        }
    }

    private static final class Frame {
        final int ifIndex;
        int elseIndex; // -1 = no ELSE seen yet
        final boolean isNotIf;

        Frame(int ifIndex, boolean isNotIf) {
            this.ifIndex = ifIndex;
            this.elseIndex = -1;
            this.isNotIf = isNotIf;
        }
    }

    private static final class Branch {
        final int ifIndex;
        final int elseIndex;
        final int endifIndex;
        final boolean isNotIf;

        Branch(int ifIndex, int elseIndex, int endifIndex, boolean isNotIf) {
            this.ifIndex = ifIndex;
            this.elseIndex = elseIndex;
            this.endifIndex = endifIndex;
            this.isNotIf = isNotIf;
        }
    }

    static PathResult analyze(List<OpStep> ops) {
        List<Finding> findings = new ArrayList<>();
        List<Branch> branches = new ArrayList<>();
        List<Frame> stack = new ArrayList<>();
        List<Integer> ifIndices = new ArrayList<>(); // op-indices of OP_IF/OP_NOTIF in source order

        boolean hasUnbalanced = false;

        for (int i = 0; i < ops.size(); i++) {
            OpStep op = ops.get(i);
            int b = op.opcode;
            if (b == Opcodes.OP_IF || b == Opcodes.OP_NOTIF) {
                stack.add(new Frame(i, b == Opcodes.OP_NOTIF));
                ifIndices.add(i);
            } else if (b == Opcodes.OP_ELSE) {
                if (stack.isEmpty()) {
                    findings.add(new Finding(
                        "error", "UNBALANCED_IF_ENDIF",
                        "OP_ELSE without matching OP_IF",
                        op.offset, op.name, null));
                    hasUnbalanced = true;
                } else {
                    stack.get(stack.size() - 1).elseIndex = i;
                }
            } else if (b == Opcodes.OP_ENDIF) {
                if (stack.isEmpty()) {
                    findings.add(new Finding(
                        "error", "UNBALANCED_IF_ENDIF",
                        "OP_ENDIF without matching OP_IF",
                        op.offset, op.name, null));
                    hasUnbalanced = true;
                } else {
                    Frame top = stack.remove(stack.size() - 1);
                    branches.add(new Branch(top.ifIndex, top.elseIndex, i, top.isNotIf));
                }
            }
        }
        // Unclosed IF/NOTIF frames.
        for (Frame f : stack) {
            OpStep op = ops.get(f.ifIndex);
            findings.add(new Finding(
                "error", "UNBALANCED_IF_ENDIF",
                op.name + " at offset " + op.offset + " has no matching OP_ENDIF",
                op.offset, op.name, null));
            hasUnbalanced = true;
        }

        if (hasUnbalanced) {
            return new PathResult(List.of(), findings, true);
        }

        // Side-tables: for each op-index of an IF/NOTIF, the matching
        // elseIndex (or -1) and endifIndex. Also a map op-index → source-order
        // position used to index into the choices vector.
        int[] elseFor = new int[ops.size()];
        int[] endifFor = new int[ops.size()];
        int[] sourceOrderOf = new int[ops.size()];
        Arrays.fill(elseFor, -1);
        Arrays.fill(endifFor, -1);
        Arrays.fill(sourceOrderOf, -1);
        for (Branch br : branches) {
            elseFor[br.ifIndex] = br.elseIndex;
            endifFor[br.ifIndex] = br.endifIndex;
        }
        for (int k = 0; k < ifIndices.size(); k++) {
            sourceOrderOf[ifIndices.get(k)] = k;
        }

        int numBranches = ifIndices.size();
        if (numBranches == 0) {
            List<OpStep> collected = new ArrayList<>();
            for (OpStep op : ops) {
                int b = op.opcode;
                if (b == Opcodes.OP_IF || b == Opcodes.OP_NOTIF
                    || b == Opcodes.OP_ELSE || b == Opcodes.OP_ENDIF) continue;
                collected.add(op);
            }
            StackAnalyzer.LinearResult lr = StackAnalyzer.analyze(collected, 0);
            String desc = "linear (no branches)";
            for (Finding f : lr.findings) {
                findings.add(f.withPath(desc));
            }
            boolean hasCheck = hasCheckSig(collected);
            findings.addAll(unconditionalSucceeds(collected, desc));
            ExecutionPath path = new ExecutionPath(
                0, desc, List.of(), true, hasCheck, lr.depthAtEnd);
            return new PathResult(List.of(path), findings, false);
        }

        // Spec v1.2 §5.1: render the path count symbolically when
        // 2^numBranches overflows the canonical TS reference's
        // safe-integer range.
        final int LARGE_BRANCH_THRESHOLD = 53;
        boolean useExactCount = numBranches < LARGE_BRANCH_THRESHOLD;
        int loopBound;
        boolean truncated;
        long exactCount = 0L;
        if (useExactCount) {
            exactCount = 1L << numBranches;
            loopBound = (int) Math.min(exactCount, (long) MAX_PATHS);
            truncated = exactCount > MAX_PATHS;
        } else {
            loopBound = MAX_PATHS;
            truncated = true;
        }

        List<ExecutionPath> paths = new ArrayList<>();
        List<Finding> perPathFindings = new ArrayList<>();
        for (int combo = 0; combo < loopBound; combo++) {
            List<Boolean> choices = new ArrayList<>(numBranches);
            for (int b = 0; b < numBranches; b++) {
                // `combo` is bounded by MAX_PATHS = 256, so bits at
                // positions >= 8 are mathematically always 0. We clamp to
                // b < 31 to match the canonical TS reference, where JS
                // `>>` (and Java `>>` on int) would otherwise mask the
                // shift count to 5 bits and wrap.
                boolean bit = (b < 31) && (((combo >> b) & 1) == 1);
                choices.add(bit);
            }
            String desc = describePath(ops, ifIndices, choices);
            List<OpStep> collected = collectPathOpcodes(
                ops, choices, elseFor, endifFor, sourceOrderOf);
            StackAnalyzer.LinearResult lr = StackAnalyzer.analyze(collected, 0);
            for (Finding f : lr.findings) {
                perPathFindings.add(f.withPath(desc));
            }
            perPathFindings.addAll(unconditionalSucceeds(collected, desc));
            boolean hasCheck = hasCheckSig(collected);
            paths.add(new ExecutionPath(
                combo, desc, choices, true, hasCheck, lr.depthAtEnd));
        }

        if (truncated) {
            String pathsClause = useExactCount
                ? ("2^" + numBranches + " = " + exactCount + " paths")
                : ("more than 2^" + LARGE_BRANCH_THRESHOLD + " paths");
            findings.add(new Finding(
                "warning", "PATHS_TRUNCATED",
                "Script has " + numBranches + " branch points ("
                    + pathsClause + "); analysis truncated to the first 256. "
                    + "Consider reducing branching or splitting the contract"
                    + " into smaller spending paths.",
                null, null, null));
        }

        findings.addAll(perPathFindings);

        // INCONSISTENT_BRANCH_DEPTH (§7.6).
        for (Branch br : branches) {
            if (br.elseIndex < 0) {
                if (containsNestedIf(ops, br.ifIndex + 1, br.endifIndex)) continue;
                int delta = flatDelta(ops, br.ifIndex + 1, br.endifIndex);
                if (delta != 0) {
                    OpStep endif = ops.get(br.endifIndex);
                    findings.add(new Finding(
                        "warning", "INCONSISTENT_BRANCH_DEPTH",
                        "OP_IF body has net stack delta " + delta
                            + "; without an OP_ELSE the depth after OP_ENDIF"
                            + " depends on the branch condition",
                        endif.offset, "OP_ENDIF", null));
                }
            } else {
                if (containsNestedIf(ops, br.ifIndex + 1, br.elseIndex)
                    || containsNestedIf(ops, br.elseIndex + 1, br.endifIndex)) continue;
                int t = flatDelta(ops, br.ifIndex + 1, br.elseIndex);
                int e = flatDelta(ops, br.elseIndex + 1, br.endifIndex);
                if (t != e) {
                    OpStep endif = ops.get(br.endifIndex);
                    findings.add(new Finding(
                        "warning", "INCONSISTENT_BRANCH_DEPTH",
                        "IF/ELSE branches leave different stack depths (THEN: "
                            + t + ", ELSE: " + e
                            + ") — code after OP_ENDIF will see a depth that"
                            + " depends on which branch ran",
                        endif.offset, "OP_ENDIF", null));
                }
            }
        }

        return new PathResult(paths, findings, false);
    }

    private static String describePath(List<OpStep> ops, List<Integer> ifIndices,
                                        List<Boolean> choices) {
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < ifIndices.size(); k++) {
            if (k > 0) sb.append(" -> ");
            OpStep op = ops.get(ifIndices.get(k));
            String label = (op.opcode == Opcodes.OP_NOTIF) ? "NOTIF" : "IF";
            boolean choice = choices.get(k);
            sb.append(label).append('[').append(choice ? "true" : "false")
                .append("] at ").append(op.offset);
        }
        return sb.toString();
    }

    /**
     * Walk the opcode list and collect executed opcodes for the given
     * choices vector. Per the reference behavior (verified against the
     * stateful-counter golden), choices are consumed in <em>traversal
     * order</em> — each IF/NOTIF encountered during the DFS pops the next
     * choice off the vector. IF/NOTIF/ELSE/ENDIF themselves are not
     * emitted into the output list.
     *
     * <p>Note: this differs from a naive "look up choice by global
     * source-order index" model. For nested IFs where an outer choice
     * skips a subtree, the inner choices are simply not consumed, and
     * any remaining choices apply to the next IF visited after the
     * skipped subtree closes. The path description in §7.3 happens to
     * pair {@code choices[k]} with the k-th IF in source order, but the
     * collection algorithm here is traversal-order serial.
     */
    private static List<OpStep> collectPathOpcodes(
        List<OpStep> ops, List<Boolean> choices,
        int[] elseFor, int[] endifFor, int[] sourceOrderOf) {
        List<OpStep> out = new ArrayList<>();
        int[] cursor = new int[]{0};
        collectRange(out, ops, 0, ops.size(), choices, cursor,
            elseFor, endifFor);
        return out;
    }

    private static void collectRange(
        List<OpStep> out, List<OpStep> ops, int from, int to,
        List<Boolean> choices, int[] cursor,
        int[] elseFor, int[] endifFor) {
        int i = from;
        while (i < to) {
            OpStep op = ops.get(i);
            int b = op.opcode;
            if (b == Opcodes.OP_IF || b == Opcodes.OP_NOTIF) {
                boolean choice;
                if (cursor[0] < choices.size()) {
                    choice = choices.get(cursor[0]);
                } else {
                    choice = true; // defensive default per §7.4
                }
                cursor[0]++;
                int elseI = elseFor[i];
                int endifI = endifFor[i];
                if (choice) {
                    int thenEnd = (elseI >= 0) ? elseI : endifI;
                    collectRange(out, ops, i + 1, thenEnd, choices, cursor,
                        elseFor, endifFor);
                } else {
                    if (elseI >= 0) {
                        collectRange(out, ops, elseI + 1, endifI, choices, cursor,
                            elseFor, endifFor);
                    }
                }
                i = endifI + 1;
            } else if (b == Opcodes.OP_ELSE || b == Opcodes.OP_ENDIF) {
                i++;
            } else {
                out.add(op);
                i++;
            }
        }
    }

    private static int flatDelta(List<OpStep> ops, int from, int to) {
        int delta = 0;
        for (int i = from; i < to; i++) {
            OpStep op = ops.get(i);
            int b = op.opcode;
            if (b == Opcodes.OP_ELSE || b == Opcodes.OP_ENDIF) continue;
            StackAnalyzer.Effect e = StackAnalyzer.effectFor(op);
            delta += e.pushes - e.pops;
        }
        return delta;
    }

    private static boolean containsNestedIf(List<OpStep> ops, int from, int to) {
        for (int i = from; i < to; i++) {
            int b = ops.get(i).opcode;
            if (b == Opcodes.OP_IF || b == Opcodes.OP_NOTIF) return true;
        }
        return false;
    }

    private static final Set<Integer> CHECKSIG_OPS = new HashSet<>();

    static {
        CHECKSIG_OPS.add(Opcodes.OP_CHECKSIG);
        CHECKSIG_OPS.add(Opcodes.OP_CHECKSIGVERIFY);
        CHECKSIG_OPS.add(Opcodes.OP_CHECKMULTISIG);
        CHECKSIG_OPS.add(Opcodes.OP_CHECKMULTISIGVERIFY);
    }

    private static boolean hasCheckSig(List<OpStep> ops) {
        for (OpStep op : ops) {
            if (CHECKSIG_OPS.contains(op.opcode)) return true;
        }
        return false;
    }

    private static final Set<Integer> VERIFY_OPS = new HashSet<>();

    static {
        VERIFY_OPS.add(Opcodes.OP_VERIFY);
        VERIFY_OPS.add(Opcodes.OP_RETURN);
        VERIFY_OPS.add(Opcodes.OP_EQUALVERIFY);
        VERIFY_OPS.add(Opcodes.OP_NUMEQUALVERIFY);
        VERIFY_OPS.add(Opcodes.OP_CHECKSIG);
        VERIFY_OPS.add(Opcodes.OP_CHECKSIGVERIFY);
        VERIFY_OPS.add(Opcodes.OP_CHECKMULTISIG);
        VERIFY_OPS.add(Opcodes.OP_CHECKMULTISIGVERIFY);
    }

    private static List<Finding> unconditionalSucceeds(List<OpStep> ops, String pathDesc) {
        if (ops.isEmpty()) return List.of();
        for (OpStep op : ops) {
            if (VERIFY_OPS.contains(op.opcode)) return List.of();
        }
        return List.of(new Finding(
            "warning", "UNCONDITIONALLY_SUCCEEDS",
            "Execution path has no verification opcode — any unlocking input will satisfy it",
            null, null, pathDesc));
    }
}
