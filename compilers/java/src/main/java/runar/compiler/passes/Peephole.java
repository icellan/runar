package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import runar.compiler.ir.stack.BigIntPushValue;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;

/**
 * Peephole optimizer — runs on Stack IR before emission.
 *
 * <p>Port of {@code packages/runar-compiler/src/optimizer/peephole.ts}.
 * Rules are applied iteratively to a fixed point, with wider windows tried
 * first so adjacent rewrites compose correctly. If-branches are optimised
 * recursively.
 */
public final class Peephole {

    private Peephole() {}

    private static final int MAX_ITERATIONS = 100;

    public static StackProgram run(StackProgram program) {
        List<StackMethod> optimised = new ArrayList<>(program.methods().size());
        for (StackMethod m : program.methods()) {
            List<StackOp> ops = optimize(m.ops());
            optimised.add(new StackMethod(m.name(), ops, m.maxStackDepth()));
        }
        return new StackProgram(program.contractName(), optimised);
    }

    public static List<StackOp> optimize(List<StackOp> ops) {
        List<StackOp> current = new ArrayList<>(ops.size());
        for (StackOp op : ops) current.add(optimizeNestedIf(op));

        for (int it = 0; it < MAX_ITERATIONS; it++) {
            Pass pass = applyOnePass(current);
            if (!pass.changed) break;
            current = pass.ops;
        }
        return current;
    }

    private static StackOp optimizeNestedIf(StackOp op) {
        if (op instanceof IfOp i) {
            List<StackOp> thenB = optimize(i.thenBranch());
            List<StackOp> elseB = i.elseBranch() != null ? optimize(i.elseBranch()) : null;
            if (elseB == null) return new IfOp(thenB);
            return new IfOp(thenB, elseB);
        }
        return op;
    }

    private static final class Pass {
        final List<StackOp> ops;
        final boolean changed;
        Pass(List<StackOp> ops, boolean changed) {
            this.ops = ops;
            this.changed = changed;
        }
    }

    private static Pass applyOnePass(List<StackOp> ops) {
        List<StackOp> out = new ArrayList<>();
        boolean changed = false;
        int i = 0;
        while (i < ops.size()) {
            // Widest window first: 4, 3, then 2.
            if (i + 4 <= ops.size()) {
                List<StackOp> r = matchWindow4(ops.get(i), ops.get(i + 1), ops.get(i + 2), ops.get(i + 3));
                if (r != null) {
                    out.addAll(r);
                    i += 4;
                    changed = true;
                    continue;
                }
            }
            if (i + 3 <= ops.size()) {
                List<StackOp> r = matchWindow3(ops.get(i), ops.get(i + 1), ops.get(i + 2));
                if (r != null) {
                    out.addAll(r);
                    i += 3;
                    changed = true;
                    continue;
                }
            }
            if (i + 2 <= ops.size()) {
                List<StackOp> r = matchWindow2(ops.get(i), ops.get(i + 1));
                if (r != null) {
                    out.addAll(r);
                    i += 2;
                    changed = true;
                    continue;
                }
            }
            out.add(ops.get(i));
            i++;
        }
        return new Pass(out, changed);
    }

    // ---------- window-2 rules ----------

    static List<StackOp> matchWindow2(StackOp a, StackOp b) {
        // PUSH x, DROP → remove both (dead value elimination)
        if (a instanceof PushOp && b instanceof DropOp) return List.of();

        // DUP, DROP → remove both
        if (a instanceof DupOp && b instanceof DropOp) return List.of();

        // SWAP, SWAP → identity
        if (a instanceof SwapOp && b instanceof SwapOp) return List.of();

        // PUSH 1, OP_ADD → OP_1ADD
        if (isPushBigInt(a, 1) && isOpcode(b, "OP_ADD")) return List.of(new OpcodeOp("OP_1ADD"));
        // PUSH 1, OP_SUB → OP_1SUB
        if (isPushBigInt(a, 1) && isOpcode(b, "OP_SUB")) return List.of(new OpcodeOp("OP_1SUB"));
        // PUSH 0, OP_ADD → identity
        if (isPushBigInt(a, 0) && isOpcode(b, "OP_ADD")) return List.of();
        // PUSH 0, OP_SUB → identity
        if (isPushBigInt(a, 0) && isOpcode(b, "OP_SUB")) return List.of();

        // OP_NOT, OP_NOT → remove both
        if (isOpcode(a, "OP_NOT") && isOpcode(b, "OP_NOT")) return List.of();
        // OP_NEGATE, OP_NEGATE → remove both
        if (isOpcode(a, "OP_NEGATE") && isOpcode(b, "OP_NEGATE")) return List.of();

        // OP_EQUAL + OP_VERIFY → OP_EQUALVERIFY
        if (isOpcode(a, "OP_EQUAL") && isOpcode(b, "OP_VERIFY")) return List.of(new OpcodeOp("OP_EQUALVERIFY"));
        // OP_CHECKSIG + OP_VERIFY → OP_CHECKSIGVERIFY
        if (isOpcode(a, "OP_CHECKSIG") && isOpcode(b, "OP_VERIFY")) return List.of(new OpcodeOp("OP_CHECKSIGVERIFY"));
        // OP_NUMEQUAL + OP_VERIFY → OP_NUMEQUALVERIFY
        if (isOpcode(a, "OP_NUMEQUAL") && isOpcode(b, "OP_VERIFY")) return List.of(new OpcodeOp("OP_NUMEQUALVERIFY"));
        // OP_CHECKMULTISIG + OP_VERIFY → OP_CHECKMULTISIGVERIFY
        if (isOpcode(a, "OP_CHECKMULTISIG") && isOpcode(b, "OP_VERIFY")) return List.of(new OpcodeOp("OP_CHECKMULTISIGVERIFY"));

        // OP_DUP + OP_DROP → remove both
        if (isOpcode(a, "OP_DUP") && isOpcode(b, "OP_DROP")) return List.of();

        // OVER + OVER → OP_2DUP
        if (a instanceof OverOp && b instanceof OverOp) return List.of(new OpcodeOp("OP_2DUP"));
        // DROP + DROP → OP_2DROP
        if (a instanceof DropOp && b instanceof DropOp) return List.of(new OpcodeOp("OP_2DROP"));

        // PUSH 0 + Roll{0} → remove both
        if (isPushBigInt(a, 0) && isRoll(b, 0)) return List.of();
        // PUSH 1 + Roll{1} → SWAP
        if (isPushBigInt(a, 1) && isRoll(b, 1)) return List.of(new SwapOp());
        // PUSH 2 + Roll{2} → ROT
        if (isPushBigInt(a, 2) && isRoll(b, 2)) return List.of(new RotOp());
        // PUSH 0 + Pick{0} → DUP
        if (isPushBigInt(a, 0) && isPick(b, 0)) return List.of(new DupOp());
        // PUSH 1 + Pick{1} → OVER
        if (isPushBigInt(a, 1) && isPick(b, 1)) return List.of(new OverOp());

        // OP_SHA256 + OP_SHA256 → OP_HASH256
        if (isOpcode(a, "OP_SHA256") && isOpcode(b, "OP_SHA256")) return List.of(new OpcodeOp("OP_HASH256"));

        // PUSH 0 + OP_NUMEQUAL → OP_NOT
        if (isPushBigInt(a, 0) && isOpcode(b, "OP_NUMEQUAL")) return List.of(new OpcodeOp("OP_NOT"));

        return null;
    }

    // ---------- window-3 rules ----------

    static List<StackOp> matchWindow3(StackOp a, StackOp b, StackOp c) {
        BigInteger av = pushBigInt(a);
        BigInteger bv = pushBigInt(b);
        if (av != null && bv != null) {
            if (isOpcode(c, "OP_ADD")) return List.of(new PushOp(PushValue.of(av.add(bv))));
            if (isOpcode(c, "OP_SUB")) return List.of(new PushOp(PushValue.of(av.subtract(bv))));
            if (isOpcode(c, "OP_MUL")) return List.of(new PushOp(PushValue.of(av.multiply(bv))));
        }
        return null;
    }

    // ---------- window-4 rules ----------

    static List<StackOp> matchWindow4(StackOp a, StackOp b, StackOp c, StackOp d) {
        BigInteger av = pushBigInt(a);
        BigInteger cv = pushBigInt(c);
        if (av != null && cv != null) {
            if (isOpcode(b, "OP_ADD") && isOpcode(d, "OP_ADD")) {
                return List.of(new PushOp(PushValue.of(av.add(cv))), new OpcodeOp("OP_ADD"));
            }
            if (isOpcode(b, "OP_SUB") && isOpcode(d, "OP_SUB")) {
                return List.of(new PushOp(PushValue.of(av.add(cv))), new OpcodeOp("OP_SUB"));
            }
        }
        return null;
    }

    // ---------- predicates ----------

    private static boolean isOpcode(StackOp op, String code) {
        return op instanceof OpcodeOp o && code.equals(o.code());
    }

    private static boolean isPushBigInt(StackOp op, long n) {
        if (!(op instanceof PushOp p)) return false;
        if (!(p.value() instanceof BigIntPushValue bi)) return false;
        return bi.value().equals(BigInteger.valueOf(n));
    }

    private static BigInteger pushBigInt(StackOp op) {
        if (op instanceof PushOp p && p.value() instanceof BigIntPushValue bi) {
            return bi.value();
        }
        return null;
    }

    private static boolean isRoll(StackOp op, long depth) {
        return op instanceof RollOp r && r.depth().equals(BigInteger.valueOf(depth));
    }

    private static boolean isPick(StackOp op, long depth) {
        return op instanceof PickOp p && p.depth().equals(BigInteger.valueOf(depth));
    }
}
