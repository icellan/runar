package runar.lang.analyzer;

/**
 * BSV opcode constants and the byte → canonical-name table used by the
 * static analyzer. Mirrors spec/script-analyzer-format.md §4.1.
 */
final class Opcodes {
    private Opcodes() {}

    static final int OP_0 = 0x00;
    static final int OP_PUSHDATA1 = 0x4c;
    static final int OP_PUSHDATA2 = 0x4d;
    static final int OP_PUSHDATA4 = 0x4e;
    static final int OP_1NEGATE = 0x4f;
    static final int OP_1 = 0x51;
    static final int OP_16 = 0x60;

    static final int OP_NOP = 0x61;
    static final int OP_IF = 0x63;
    static final int OP_NOTIF = 0x64;
    static final int OP_ELSE = 0x67;
    static final int OP_ENDIF = 0x68;
    static final int OP_VERIFY = 0x69;
    static final int OP_RETURN = 0x6a;

    static final int OP_DROP = 0x75;
    static final int OP_EQUALVERIFY = 0x88;
    static final int OP_NUMEQUALVERIFY = 0x9d;
    static final int OP_CODESEPARATOR = 0xab;
    static final int OP_CHECKSIG = 0xac;
    static final int OP_CHECKSIGVERIFY = 0xad;
    static final int OP_CHECKMULTISIG = 0xae;
    static final int OP_CHECKMULTISIGVERIFY = 0xaf;

    private static final String[] NAMES = new String[256];

    static {
        NAMES[0x00] = "OP_0";
        NAMES[0x4c] = "OP_PUSHDATA1";
        NAMES[0x4d] = "OP_PUSHDATA2";
        NAMES[0x4e] = "OP_PUSHDATA4";
        NAMES[0x4f] = "OP_1NEGATE";
        NAMES[0x51] = "OP_1";
        NAMES[0x52] = "OP_2";
        NAMES[0x53] = "OP_3";
        NAMES[0x54] = "OP_4";
        NAMES[0x55] = "OP_5";
        NAMES[0x56] = "OP_6";
        NAMES[0x57] = "OP_7";
        NAMES[0x58] = "OP_8";
        NAMES[0x59] = "OP_9";
        NAMES[0x5a] = "OP_10";
        NAMES[0x5b] = "OP_11";
        NAMES[0x5c] = "OP_12";
        NAMES[0x5d] = "OP_13";
        NAMES[0x5e] = "OP_14";
        NAMES[0x5f] = "OP_15";
        NAMES[0x60] = "OP_16";

        NAMES[0x61] = "OP_NOP";
        NAMES[0x63] = "OP_IF";
        NAMES[0x64] = "OP_NOTIF";
        NAMES[0x67] = "OP_ELSE";
        NAMES[0x68] = "OP_ENDIF";
        NAMES[0x69] = "OP_VERIFY";
        NAMES[0x6a] = "OP_RETURN";
        NAMES[0x6b] = "OP_TOALTSTACK";
        NAMES[0x6c] = "OP_FROMALTSTACK";
        NAMES[0x6d] = "OP_2DROP";
        NAMES[0x6e] = "OP_2DUP";
        NAMES[0x6f] = "OP_3DUP";
        NAMES[0x70] = "OP_2OVER";
        NAMES[0x71] = "OP_2ROT";
        NAMES[0x72] = "OP_2SWAP";
        NAMES[0x73] = "OP_IFDUP";
        NAMES[0x74] = "OP_DEPTH";
        NAMES[0x75] = "OP_DROP";
        NAMES[0x76] = "OP_DUP";
        NAMES[0x77] = "OP_NIP";
        NAMES[0x78] = "OP_OVER";
        NAMES[0x79] = "OP_PICK";
        NAMES[0x7a] = "OP_ROLL";
        NAMES[0x7b] = "OP_ROT";
        NAMES[0x7c] = "OP_SWAP";
        NAMES[0x7d] = "OP_TUCK";
        NAMES[0x7e] = "OP_CAT";
        NAMES[0x7f] = "OP_SPLIT";
        NAMES[0x80] = "OP_NUM2BIN";
        NAMES[0x81] = "OP_BIN2NUM";
        NAMES[0x82] = "OP_SIZE";
        NAMES[0x83] = "OP_INVERT";
        NAMES[0x84] = "OP_AND";
        NAMES[0x85] = "OP_OR";
        NAMES[0x86] = "OP_XOR";
        NAMES[0x87] = "OP_EQUAL";
        NAMES[0x88] = "OP_EQUALVERIFY";
        NAMES[0x8b] = "OP_1ADD";
        NAMES[0x8c] = "OP_1SUB";
        NAMES[0x8f] = "OP_NEGATE";
        NAMES[0x90] = "OP_ABS";
        NAMES[0x91] = "OP_NOT";
        NAMES[0x92] = "OP_0NOTEQUAL";
        NAMES[0x93] = "OP_ADD";
        NAMES[0x94] = "OP_SUB";
        NAMES[0x95] = "OP_MUL";
        NAMES[0x96] = "OP_DIV";
        NAMES[0x97] = "OP_MOD";
        NAMES[0x98] = "OP_LSHIFT";
        NAMES[0x99] = "OP_RSHIFT";
        NAMES[0x9a] = "OP_BOOLAND";
        NAMES[0x9b] = "OP_BOOLOR";
        NAMES[0x9c] = "OP_NUMEQUAL";
        NAMES[0x9d] = "OP_NUMEQUALVERIFY";
        NAMES[0x9e] = "OP_NUMNOTEQUAL";
        NAMES[0x9f] = "OP_LESSTHAN";
        NAMES[0xa0] = "OP_GREATERTHAN";
        NAMES[0xa1] = "OP_LESSTHANOREQUAL";
        NAMES[0xa2] = "OP_GREATERTHANOREQUAL";
        NAMES[0xa3] = "OP_MIN";
        NAMES[0xa4] = "OP_MAX";
        NAMES[0xa5] = "OP_WITHIN";
        NAMES[0xa6] = "OP_RIPEMD160";
        NAMES[0xa7] = "OP_SHA1";
        NAMES[0xa8] = "OP_SHA256";
        NAMES[0xa9] = "OP_HASH160";
        NAMES[0xaa] = "OP_HASH256";
        NAMES[0xab] = "OP_CODESEPARATOR";
        NAMES[0xac] = "OP_CHECKSIG";
        NAMES[0xad] = "OP_CHECKSIGVERIFY";
        NAMES[0xae] = "OP_CHECKMULTISIG";
        NAMES[0xaf] = "OP_CHECKMULTISIGVERIFY";
    }

    /**
     * Canonical name for an opcode byte. Direct-push bytes (0x01..0x4b)
     * and unknown bytes do NOT have a canonical name here — the parser
     * computes those when emitting an OpStep ("PUSH_n" and "OP_UNKNOWN(0xNN)").
     */
    static String nameOf(int op) {
        if (op < 0 || op > 0xff) return null;
        return NAMES[op];
    }
}
