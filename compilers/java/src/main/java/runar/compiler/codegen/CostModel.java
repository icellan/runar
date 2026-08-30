package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.List;
import runar.compiler.ir.stack.BigIntPushValue;
import runar.compiler.ir.stack.BoolPushValue;
import runar.compiler.ir.stack.ByteStringPushValue;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PlaceholderOp;
import runar.compiler.ir.stack.PushCodeSepIndexOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RawBytesOp;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.SwapOp;
import runar.compiler.ir.stack.TuckOp;
import runar.compiler.passes.Emit;

/**
 * Script-byte cost model for Stack IR.
 *
 * <p>Port of {@code packages/runar-compiler/src/metrics/cost-model.ts}. Optimizer passes need to
 * compare two candidate lowerings by the metric that actually matters — serialized locking-script
 * bytes — before either one is emitted. {@code OP_DUP} and a 33-byte constant push are one
 * instruction each and 1 vs 34 bytes; an instruction count cannot tell them apart.
 *
 * <p>This is deliberately NOT an approximation: every push routes through the same encoders {@code
 * Emit} uses, so
 *
 * <pre>{@code
 * estimateScriptBytes(ops) == emitted hex length / 2
 * }</pre>
 *
 * holds exactly. {@code CostModelTest} asserts that over every crypto emitter.
 */
public final class CostModel {

    private CostModel() {}

    /**
     * Serialized byte cost of a single push value.
     *
     * <p>Mirrors {@code Emit.encodePushValue}: booleans are the 1-byte OP_TRUE / OP_FALSE, integers
     * go through the small-int opcodes where possible, and byte arrays are MINIMALDATA-aware before
     * falling back to a length-prefixed push.
     */
    public static int sizeOfPushValue(PushValue value) {
        if (value instanceof BoolPushValue) {
            return 1;
        }
        if (value instanceof BigIntPushValue b) {
            return Emit.encodePushBigIntHex(b.value()).length() / 2;
        }
        if (value instanceof ByteStringPushValue s) {
            return Emit.encodePushBytesHex(hexToBytes(s.hex())).length() / 2;
        }
        throw new IllegalArgumentException("cost-model: unknown push value " + value);
    }

    /**
     * {@link #sizeOfPushValue} for a bare integer — what the constant pool and the comb width search
     * compare against.
     */
    public static int sizeOfPushInt(BigInteger n) {
        return Emit.encodePushBigIntHex(n).length() / 2;
    }

    /**
     * Serialized byte cost of one Stack IR operation, including nested {@code if} arms.
     *
     * <p>Note on {@code PickOp} / {@code RollOp}: they cost ONE byte here. The depth operand is a
     * separate {@code PushOp} that the tracker emits immediately before, so charging the depth here
     * would double-count it.
     *
     * <p>Throws on an unknown opcode mnemonic rather than costing it zero — a typo in a codegen
     * module should surface loudly, not as a cost model that quietly under-reports.
     */
    public static int sizeOfStackOp(StackOp op) {
        if (op instanceof PushOp p) {
            return sizeOfPushValue(p.value());
        }
        if (op instanceof DupOp
                || op instanceof SwapOp
                || op instanceof RollOp
                || op instanceof PickOp
                || op instanceof DropOp
                || op instanceof NipOp
                || op instanceof OverOp
                || op instanceof RotOp
                || op instanceof TuckOp) {
            return 1;
        }
        if (op instanceof OpcodeOp o) {
            if (!Emit.OPCODES.containsKey(o.code())) {
                throw new RuntimeException("cost-model: unknown opcode '" + o.code() + "'");
            }
            return 1;
        }
        if (op instanceof IfOp i) {
            // OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
            // OP_ELSE only for a NON-EMPTY else arm.
            int total = 2;
            total += estimateScriptBytes(i.thenBranch());
            if (i.elseBranch() != null && !i.elseBranch().isEmpty()) {
                total += 1 + estimateScriptBytes(i.elseBranch());
            }
            return total;
        }
        if (op instanceof PlaceholderOp || op instanceof PushCodeSepIndexOp) {
            // Both emit a single 0x00 byte that the SDK rewrites later.
            return 1;
        }
        if (op instanceof RawBytesOp r) {
            return r.bytes().length;
        }
        throw new RuntimeException("cost-model: unknown stack op " + op.getClass().getSimpleName());
    }

    /** Serialized byte cost of a Stack IR sequence. */
    public static int estimateScriptBytes(List<StackOp> ops) {
        int total = 0;
        for (StackOp op : ops) {
            total += sizeOfStackOp(op);
        }
        return total;
    }

    private static byte[] hexToBytes(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
