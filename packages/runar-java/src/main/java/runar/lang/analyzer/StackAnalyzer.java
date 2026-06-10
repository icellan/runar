package runar.lang.analyzer;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-opcode stack effects (spec §8.1) and the linear stack analysis
 * algorithm (spec §8.2).
 */
final class StackAnalyzer {
    private StackAnalyzer() {}

    static final class Effect {
        final int pops;
        final int pushes;

        Effect(int pops, int pushes) {
            this.pops = pops;
            this.pushes = pushes;
        }
    }

    private static final Effect[] TABLE = new Effect[256];
    private static final Effect ZERO = new Effect(0, 0);

    static {
        TABLE[0x61] = new Effect(0, 0); // OP_NOP
        TABLE[0x63] = new Effect(1, 0); // OP_IF
        TABLE[0x64] = new Effect(1, 0); // OP_NOTIF
        TABLE[0x67] = new Effect(0, 0); // OP_ELSE
        TABLE[0x68] = new Effect(0, 0); // OP_ENDIF
        TABLE[0x69] = new Effect(1, 0); // OP_VERIFY
        TABLE[0x6a] = new Effect(0, 0); // OP_RETURN
        TABLE[0x6b] = new Effect(1, 0); // OP_TOALTSTACK
        TABLE[0x6c] = new Effect(0, 1); // OP_FROMALTSTACK
        TABLE[0x6d] = new Effect(2, 0); // OP_2DROP
        TABLE[0x6e] = new Effect(2, 4); // OP_2DUP
        TABLE[0x6f] = new Effect(3, 6); // OP_3DUP
        TABLE[0x70] = new Effect(4, 6); // OP_2OVER
        TABLE[0x71] = new Effect(6, 6); // OP_2ROT
        TABLE[0x72] = new Effect(4, 4); // OP_2SWAP
        TABLE[0x73] = new Effect(1, 1); // OP_IFDUP
        TABLE[0x74] = new Effect(0, 1); // OP_DEPTH
        TABLE[0x75] = new Effect(1, 0); // OP_DROP
        TABLE[0x76] = new Effect(1, 2); // OP_DUP
        TABLE[0x77] = new Effect(2, 1); // OP_NIP
        TABLE[0x78] = new Effect(2, 3); // OP_OVER
        TABLE[0x79] = new Effect(1, 1); // OP_PICK
        TABLE[0x7a] = new Effect(1, 0); // OP_ROLL
        TABLE[0x7b] = new Effect(3, 3); // OP_ROT
        TABLE[0x7c] = new Effect(2, 2); // OP_SWAP
        TABLE[0x7d] = new Effect(2, 3); // OP_TUCK
        TABLE[0x7e] = new Effect(2, 1); // OP_CAT
        TABLE[0x7f] = new Effect(2, 2); // OP_SPLIT
        TABLE[0x80] = new Effect(2, 1); // OP_NUM2BIN
        TABLE[0x81] = new Effect(1, 1); // OP_BIN2NUM
        TABLE[0x82] = new Effect(1, 2); // OP_SIZE
        TABLE[0x83] = new Effect(1, 1); // OP_INVERT
        TABLE[0x84] = new Effect(2, 1); // OP_AND
        TABLE[0x85] = new Effect(2, 1); // OP_OR
        TABLE[0x86] = new Effect(2, 1); // OP_XOR
        TABLE[0x87] = new Effect(2, 1); // OP_EQUAL
        TABLE[0x88] = new Effect(2, 0); // OP_EQUALVERIFY
        TABLE[0x8b] = new Effect(1, 1); // OP_1ADD
        TABLE[0x8c] = new Effect(1, 1); // OP_1SUB
        TABLE[0x8f] = new Effect(1, 1); // OP_NEGATE
        TABLE[0x90] = new Effect(1, 1); // OP_ABS
        TABLE[0x91] = new Effect(1, 1); // OP_NOT
        TABLE[0x92] = new Effect(1, 1); // OP_0NOTEQUAL
        TABLE[0x93] = new Effect(2, 1); // OP_ADD
        TABLE[0x94] = new Effect(2, 1); // OP_SUB
        TABLE[0x95] = new Effect(2, 1); // OP_MUL
        TABLE[0x96] = new Effect(2, 1); // OP_DIV
        TABLE[0x97] = new Effect(2, 1); // OP_MOD
        TABLE[0x98] = new Effect(2, 1); // OP_LSHIFT
        TABLE[0x99] = new Effect(2, 1); // OP_RSHIFT
        TABLE[0x9a] = new Effect(2, 1); // OP_BOOLAND
        TABLE[0x9b] = new Effect(2, 1); // OP_BOOLOR
        TABLE[0x9c] = new Effect(2, 1); // OP_NUMEQUAL
        TABLE[0x9d] = new Effect(2, 0); // OP_NUMEQUALVERIFY
        TABLE[0x9e] = new Effect(2, 1); // OP_NUMNOTEQUAL
        TABLE[0x9f] = new Effect(2, 1); // OP_LESSTHAN
        TABLE[0xa0] = new Effect(2, 1); // OP_GREATERTHAN
        TABLE[0xa1] = new Effect(2, 1); // OP_LESSTHANOREQUAL
        TABLE[0xa2] = new Effect(2, 1); // OP_GREATERTHANOREQUAL
        TABLE[0xa3] = new Effect(2, 1); // OP_MIN
        TABLE[0xa4] = new Effect(2, 1); // OP_MAX
        TABLE[0xa5] = new Effect(3, 1); // OP_WITHIN
        TABLE[0xa6] = new Effect(1, 1); // OP_RIPEMD160
        TABLE[0xa7] = new Effect(1, 1); // OP_SHA1
        TABLE[0xa8] = new Effect(1, 1); // OP_SHA256
        TABLE[0xa9] = new Effect(1, 1); // OP_HASH160
        TABLE[0xaa] = new Effect(1, 1); // OP_HASH256
        TABLE[0xac] = new Effect(2, 1); // OP_CHECKSIG
        TABLE[0xad] = new Effect(2, 0); // OP_CHECKSIGVERIFY
        TABLE[0xae] = new Effect(3, 1); // OP_CHECKMULTISIG
        TABLE[0xaf] = new Effect(3, 0); // OP_CHECKMULTISIGVERIFY
    }

    static Effect effectFor(OpStep op) {
        if (op.opcode == -1) {
            return new Effect(op.rawSpanIn, op.rawSpanOut);
        }
        // Any push: (0, 1).
        if (op.pushEncoding != null) {
            return new Effect(0, 1);
        }
        // OP_1NEGATE and OP_1..OP_16 — those are pushes too, and parse
        // creates them as OpStep.op(...) (no pushEncoding). Spec §8.1
        // says "Any push operation: (0, 1)" and §6 classifies these as
        // "opN" pushes. Honor that.
        int b = op.opcode;
        if (b == 0x00 || b == 0x4f || (b >= 0x51 && b <= 0x60)) {
            return new Effect(0, 1);
        }
        Effect e = TABLE[b & 0xff];
        return e == null ? ZERO : e;
    }

    /** Result of the linear-analysis algorithm. */
    static final class LinearResult {
        final int depthAtEnd;
        final int maxDepth;
        final List<Finding> findings;

        LinearResult(int depthAtEnd, int maxDepth, List<Finding> findings) {
            this.depthAtEnd = depthAtEnd;
            this.maxDepth = maxDepth;
            this.findings = findings;
        }
    }

    /**
     * Linear stack analysis per spec §8.2.
     *
     * @param ops          opcodes in source order (the collected
     *                     per-path opcode list when called from the
     *                     path analyzer)
     * @param initialDepth initial stack depth; 0 for the top-level
     *                     locking script
     */
    static LinearResult analyze(List<OpStep> ops, int initialDepth) {
        int depth = initialDepth;
        int maxDepth = initialDepth;
        boolean afterReturn = false;
        List<Finding> findings = new ArrayList<>();
        for (OpStep op : ops) {
            if (afterReturn) {
                findings.add(new Finding(
                    "warning", "UNREACHABLE_AFTER_RETURN",
                    "Unreachable opcode " + op.name + " after OP_RETURN",
                    op.offset, op.name, null));
                continue;
            }
            if (op.opcode == Opcodes.OP_RETURN) {
                afterReturn = true;
                continue;
            }
            Effect e = effectFor(op);
            // Spec §8.2 step 4: only flag when initialDepth > 0 && depth < pops.
            if (initialDepth > 0 && depth < e.pops) {
                findings.add(new Finding(
                    "error", "STACK_UNDERFLOW",
                    op.name + " requires " + e.pops + " stack item(s) but only "
                        + depth + " available",
                    op.offset, op.name, null));
            }
            depth = depth - e.pops + e.pushes;
            if (depth > maxDepth) {
                maxDepth = depth;
            }
        }
        return new LinearResult(depth, maxDepth, findings);
    }
}
