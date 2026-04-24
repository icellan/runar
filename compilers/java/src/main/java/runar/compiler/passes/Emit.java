package runar.compiler.passes;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;
import runar.compiler.ir.stack.TuckOp;

/**
 * Stack IR → Bitcoin Script hex emission (Pass 6).
 *
 * <p>Port of {@code packages/runar-compiler/src/passes/06-emit.ts}. Walks
 * each {@link StackOp} and encodes it as Bitcoin Script bytes, producing a
 * lowercase hex string. Handles push-data sizing (direct / OP_PUSHDATA1/2/4),
 * script-number sign-magnitude encoding, and multi-method dispatch.
 */
public final class Emit {

    private Emit() {}

    // ------------------------------------------------------------------
    // Opcode table
    // ------------------------------------------------------------------

    static final Map<String, Integer> OPCODES = new HashMap<>();
    static {
        OPCODES.put("OP_0", 0x00);
        OPCODES.put("OP_FALSE", 0x00);
        OPCODES.put("OP_PUSHDATA1", 0x4c);
        OPCODES.put("OP_PUSHDATA2", 0x4d);
        OPCODES.put("OP_PUSHDATA4", 0x4e);
        OPCODES.put("OP_1NEGATE", 0x4f);
        OPCODES.put("OP_1", 0x51);
        OPCODES.put("OP_TRUE", 0x51);
        OPCODES.put("OP_2", 0x52);
        OPCODES.put("OP_3", 0x53);
        OPCODES.put("OP_4", 0x54);
        OPCODES.put("OP_5", 0x55);
        OPCODES.put("OP_6", 0x56);
        OPCODES.put("OP_7", 0x57);
        OPCODES.put("OP_8", 0x58);
        OPCODES.put("OP_9", 0x59);
        OPCODES.put("OP_10", 0x5a);
        OPCODES.put("OP_11", 0x5b);
        OPCODES.put("OP_12", 0x5c);
        OPCODES.put("OP_13", 0x5d);
        OPCODES.put("OP_14", 0x5e);
        OPCODES.put("OP_15", 0x5f);
        OPCODES.put("OP_16", 0x60);
        OPCODES.put("OP_NOP", 0x61);
        OPCODES.put("OP_IF", 0x63);
        OPCODES.put("OP_NOTIF", 0x64);
        OPCODES.put("OP_ELSE", 0x67);
        OPCODES.put("OP_ENDIF", 0x68);
        OPCODES.put("OP_VERIFY", 0x69);
        OPCODES.put("OP_RETURN", 0x6a);
        OPCODES.put("OP_TOALTSTACK", 0x6b);
        OPCODES.put("OP_FROMALTSTACK", 0x6c);
        OPCODES.put("OP_2DROP", 0x6d);
        OPCODES.put("OP_2DUP", 0x6e);
        OPCODES.put("OP_3DUP", 0x6f);
        OPCODES.put("OP_2OVER", 0x70);
        OPCODES.put("OP_2ROT", 0x71);
        OPCODES.put("OP_2SWAP", 0x72);
        OPCODES.put("OP_IFDUP", 0x73);
        OPCODES.put("OP_DEPTH", 0x74);
        OPCODES.put("OP_DROP", 0x75);
        OPCODES.put("OP_DUP", 0x76);
        OPCODES.put("OP_NIP", 0x77);
        OPCODES.put("OP_OVER", 0x78);
        OPCODES.put("OP_PICK", 0x79);
        OPCODES.put("OP_ROLL", 0x7a);
        OPCODES.put("OP_ROT", 0x7b);
        OPCODES.put("OP_SWAP", 0x7c);
        OPCODES.put("OP_TUCK", 0x7d);
        OPCODES.put("OP_CAT", 0x7e);
        OPCODES.put("OP_SPLIT", 0x7f);
        OPCODES.put("OP_NUM2BIN", 0x80);
        OPCODES.put("OP_BIN2NUM", 0x81);
        OPCODES.put("OP_SIZE", 0x82);
        OPCODES.put("OP_INVERT", 0x83);
        OPCODES.put("OP_AND", 0x84);
        OPCODES.put("OP_OR", 0x85);
        OPCODES.put("OP_XOR", 0x86);
        OPCODES.put("OP_EQUAL", 0x87);
        OPCODES.put("OP_EQUALVERIFY", 0x88);
        OPCODES.put("OP_1ADD", 0x8b);
        OPCODES.put("OP_1SUB", 0x8c);
        OPCODES.put("OP_2MUL", 0x8d);
        OPCODES.put("OP_2DIV", 0x8e);
        OPCODES.put("OP_NEGATE", 0x8f);
        OPCODES.put("OP_ABS", 0x90);
        OPCODES.put("OP_NOT", 0x91);
        OPCODES.put("OP_0NOTEQUAL", 0x92);
        OPCODES.put("OP_ADD", 0x93);
        OPCODES.put("OP_SUB", 0x94);
        OPCODES.put("OP_MUL", 0x95);
        OPCODES.put("OP_DIV", 0x96);
        OPCODES.put("OP_MOD", 0x97);
        OPCODES.put("OP_LSHIFT", 0x98);
        OPCODES.put("OP_RSHIFT", 0x99);
        OPCODES.put("OP_BOOLAND", 0x9a);
        OPCODES.put("OP_BOOLOR", 0x9b);
        OPCODES.put("OP_NUMEQUAL", 0x9c);
        OPCODES.put("OP_NUMEQUALVERIFY", 0x9d);
        OPCODES.put("OP_NUMNOTEQUAL", 0x9e);
        OPCODES.put("OP_LESSTHAN", 0x9f);
        OPCODES.put("OP_GREATERTHAN", 0xa0);
        OPCODES.put("OP_LESSTHANOREQUAL", 0xa1);
        OPCODES.put("OP_GREATERTHANOREQUAL", 0xa2);
        OPCODES.put("OP_MIN", 0xa3);
        OPCODES.put("OP_MAX", 0xa4);
        OPCODES.put("OP_WITHIN", 0xa5);
        OPCODES.put("OP_RIPEMD160", 0xa6);
        OPCODES.put("OP_SHA1", 0xa7);
        OPCODES.put("OP_SHA256", 0xa8);
        OPCODES.put("OP_HASH160", 0xa9);
        OPCODES.put("OP_HASH256", 0xaa);
        OPCODES.put("OP_CODESEPARATOR", 0xab);
        OPCODES.put("OP_CHECKSIG", 0xac);
        OPCODES.put("OP_CHECKSIGVERIFY", 0xad);
        OPCODES.put("OP_CHECKMULTISIG", 0xae);
        OPCODES.put("OP_CHECKMULTISIGVERIFY", 0xaf);
        OPCODES.put("OP_SUBSTR", 0xb3);
        OPCODES.put("OP_LEFT", 0xb4);
        OPCODES.put("OP_RIGHT", 0xb5);
        OPCODES.put("OP_LSHIFTNUM", 0xb6);
        OPCODES.put("OP_RSHIFTNUM", 0xb7);
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    public static String run(StackProgram program) {
        Ctx ctx = new Ctx();

        List<StackMethod> publicMethods = new java.util.ArrayList<>();
        for (StackMethod m : program.methods()) {
            if (!"constructor".equals(m.name())) publicMethods.add(m);
        }

        if (publicMethods.isEmpty()) return "";

        if (publicMethods.size() == 1) {
            for (StackOp op : publicMethods.get(0).ops()) emitStackOp(op, ctx);
        } else {
            emitMethodDispatch(publicMethods, ctx);
        }

        return ctx.hex.toString();
    }

    private static void emitMethodDispatch(List<StackMethod> methods, Ctx ctx) {
        for (int i = 0; i < methods.size(); i++) {
            StackMethod m = methods.get(i);
            boolean isLast = i == methods.size() - 1;
            if (!isLast) {
                ctx.emitOpcode("OP_DUP");
                ctx.emitPush(PushValue.of(i));
                ctx.emitOpcode("OP_NUMEQUAL");
                ctx.emitOpcode("OP_IF");
                ctx.emitOpcode("OP_DROP");
            } else {
                ctx.emitPush(PushValue.of(i));
                ctx.emitOpcode("OP_NUMEQUALVERIFY");
            }
            for (StackOp op : m.ops()) emitStackOp(op, ctx);
            if (!isLast) ctx.emitOpcode("OP_ELSE");
        }
        for (int i = 0; i < methods.size() - 1; i++) {
            ctx.emitOpcode("OP_ENDIF");
        }
    }

    private static void emitStackOp(StackOp op, Ctx ctx) {
        if (op instanceof PushOp p) {
            ctx.emitPush(p.value());
        } else if (op instanceof DupOp) {
            ctx.emitOpcode("OP_DUP");
        } else if (op instanceof SwapOp) {
            ctx.emitOpcode("OP_SWAP");
        } else if (op instanceof RollOp) {
            ctx.emitOpcode("OP_ROLL");
        } else if (op instanceof PickOp) {
            ctx.emitOpcode("OP_PICK");
        } else if (op instanceof DropOp) {
            ctx.emitOpcode("OP_DROP");
        } else if (op instanceof NipOp) {
            ctx.emitOpcode("OP_NIP");
        } else if (op instanceof OverOp) {
            ctx.emitOpcode("OP_OVER");
        } else if (op instanceof RotOp) {
            ctx.emitOpcode("OP_ROT");
        } else if (op instanceof TuckOp) {
            ctx.emitOpcode("OP_TUCK");
        } else if (op instanceof OpcodeOp o) {
            ctx.emitOpcode(o.code());
        } else if (op instanceof IfOp ifo) {
            emitIf(ifo.thenBranch(), ifo.elseBranch(), ctx);
        } else if (op instanceof PlaceholderOp) {
            ctx.appendHex("00");
        } else if (op instanceof PushCodeSepIndexOp) {
            ctx.appendHex("00");
        }
    }

    private static void emitIf(List<StackOp> thenOps, List<StackOp> elseOps, Ctx ctx) {
        ctx.emitOpcode("OP_IF");
        for (StackOp op : thenOps) emitStackOp(op, ctx);
        if (elseOps != null && !elseOps.isEmpty()) {
            ctx.emitOpcode("OP_ELSE");
            for (StackOp op : elseOps) emitStackOp(op, ctx);
        }
        ctx.emitOpcode("OP_ENDIF");
    }

    // ------------------------------------------------------------------
    // EmitContext
    // ------------------------------------------------------------------

    private static final class Ctx {
        final StringBuilder hex = new StringBuilder();

        void appendHex(String s) { hex.append(s); }

        void emitOpcode(String name) {
            Integer b = OPCODES.get(name);
            if (b == null) throw new RuntimeException("Unknown opcode: " + name);
            hex.append(byteToHex(b));
        }

        void emitPush(PushValue value) {
            appendHex(encodePushValue(value));
        }
    }

    // ------------------------------------------------------------------
    // Script number encoding
    // ------------------------------------------------------------------

    static byte[] encodeScriptNumber(BigInteger n) {
        if (n.signum() == 0) return new byte[0];
        boolean neg = n.signum() < 0;
        BigInteger abs = neg ? n.negate() : n;

        java.util.List<Integer> bytes = new java.util.ArrayList<>();
        BigInteger work = abs;
        while (work.signum() > 0) {
            bytes.add(work.and(BigInteger.valueOf(0xff)).intValue());
            work = work.shiftRight(8);
        }

        int lastIdx = bytes.size() - 1;
        int last = bytes.get(lastIdx);
        if ((last & 0x80) != 0) {
            bytes.add(neg ? 0x80 : 0x00);
        } else if (neg) {
            bytes.set(lastIdx, last | 0x80);
        }

        byte[] out = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) out[i] = (byte) (bytes.get(i) & 0xff);
        return out;
    }

    // ------------------------------------------------------------------
    // Push encoding
    // ------------------------------------------------------------------

    static String encodePushValue(PushValue value) {
        if (value instanceof BoolPushValue b) {
            return b.value() ? "51" : "00";
        }
        if (value instanceof BigIntPushValue i) {
            return encodePushBigInt(i.value());
        }
        if (value instanceof ByteStringPushValue bs) {
            byte[] data = hexToBytes(bs.hex());
            if (data.length == 0) return "00";
            if (data.length == 1) {
                int b = data[0] & 0xff;
                if (b >= 1 && b <= 16) return byteToHex(0x50 + b);
                if (b == 0x81) return "4f";
            }
            return bytesToHex(encodePushData(data));
        }
        throw new RuntimeException("unknown push value type");
    }

    private static String encodePushBigInt(BigInteger n) {
        if (n.signum() == 0) return "00";
        if (n.equals(BigInteger.valueOf(-1))) return "4f";
        if (n.signum() > 0 && n.compareTo(BigInteger.valueOf(16)) <= 0) {
            return byteToHex(0x50 + n.intValue());
        }
        byte[] numBytes = encodeScriptNumber(n);
        return bytesToHex(encodePushData(numBytes));
    }

    static byte[] encodePushData(byte[] data) {
        int len = data.length;
        if (len == 0) return new byte[] { 0x00 };
        if (len >= 1 && len <= 75) {
            byte[] out = new byte[1 + len];
            out[0] = (byte) len;
            System.arraycopy(data, 0, out, 1, len);
            return out;
        }
        if (len <= 255) {
            byte[] out = new byte[2 + len];
            out[0] = 0x4c;
            out[1] = (byte) len;
            System.arraycopy(data, 0, out, 2, len);
            return out;
        }
        if (len <= 65535) {
            byte[] out = new byte[3 + len];
            out[0] = 0x4d;
            out[1] = (byte) (len & 0xff);
            out[2] = (byte) ((len >> 8) & 0xff);
            System.arraycopy(data, 0, out, 3, len);
            return out;
        }
        byte[] out = new byte[5 + len];
        out[0] = 0x4e;
        out[1] = (byte) (len & 0xff);
        out[2] = (byte) ((len >> 8) & 0xff);
        out[3] = (byte) ((len >> 16) & 0xff);
        out[4] = (byte) ((len >> 24) & 0xff);
        System.arraycopy(data, 0, out, 5, len);
        return out;
    }

    // ------------------------------------------------------------------
    // Hex utilities
    // ------------------------------------------------------------------

    static String byteToHex(int b) {
        return String.format("%02x", b & 0xff);
    }

    static String bytesToHex(byte[] bs) {
        StringBuilder sb = new StringBuilder(bs.length * 2);
        for (byte b : bs) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        if ((hex.length() & 1) == 1) throw new RuntimeException("odd-length hex: " + hex);
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new RuntimeException("invalid hex: " + hex);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
