//! Complete BSV opcode table.
//!
//! This covers the full set of opcodes supported in Bitcoin SV, including
//! opcodes that were disabled in BTC but re-enabled in BSV (OP_CAT, OP_SPLIT,
//! OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT, OP_AND, OP_OR, OP_XOR).

use std::collections::HashMap;
use std::sync::LazyLock;

/// Map from opcode name to byte value.
pub static OPCODES: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // Push value
    m.insert("OP_0", 0x00);
    m.insert("OP_FALSE", 0x00);
    m.insert("OP_PUSHDATA1", 0x4c);
    m.insert("OP_PUSHDATA2", 0x4d);
    m.insert("OP_PUSHDATA4", 0x4e);
    m.insert("OP_1NEGATE", 0x4f);
    m.insert("OP_1", 0x51);
    m.insert("OP_TRUE", 0x51);
    m.insert("OP_2", 0x52);
    m.insert("OP_3", 0x53);
    m.insert("OP_4", 0x54);
    m.insert("OP_5", 0x55);
    m.insert("OP_6", 0x56);
    m.insert("OP_7", 0x57);
    m.insert("OP_8", 0x58);
    m.insert("OP_9", 0x59);
    m.insert("OP_10", 0x5a);
    m.insert("OP_11", 0x5b);
    m.insert("OP_12", 0x5c);
    m.insert("OP_13", 0x5d);
    m.insert("OP_14", 0x5e);
    m.insert("OP_15", 0x5f);
    m.insert("OP_16", 0x60);

    // Flow control
    m.insert("OP_NOP", 0x61);
    m.insert("OP_IF", 0x63);
    m.insert("OP_NOTIF", 0x64);
    m.insert("OP_ELSE", 0x67);
    m.insert("OP_ENDIF", 0x68);
    m.insert("OP_VERIFY", 0x69);
    m.insert("OP_RETURN", 0x6a);

    // Stack
    m.insert("OP_TOALTSTACK", 0x6b);
    m.insert("OP_FROMALTSTACK", 0x6c);
    m.insert("OP_2DROP", 0x6d);
    m.insert("OP_2DUP", 0x6e);
    m.insert("OP_3DUP", 0x6f);
    m.insert("OP_2OVER", 0x70);
    m.insert("OP_2ROT", 0x71);
    m.insert("OP_2SWAP", 0x72);
    m.insert("OP_IFDUP", 0x73);
    m.insert("OP_DEPTH", 0x74);
    m.insert("OP_DROP", 0x75);
    m.insert("OP_DUP", 0x76);
    m.insert("OP_NIP", 0x77);
    m.insert("OP_OVER", 0x78);
    m.insert("OP_PICK", 0x79);
    m.insert("OP_ROLL", 0x7a);
    m.insert("OP_ROT", 0x7b);
    m.insert("OP_SWAP", 0x7c);
    m.insert("OP_TUCK", 0x7d);

    // String / byte-string operations (BSV re-enabled)
    m.insert("OP_CAT", 0x7e);
    m.insert("OP_SPLIT", 0x7f);
    m.insert("OP_NUM2BIN", 0x80);
    m.insert("OP_BIN2NUM", 0x81);
    m.insert("OP_SIZE", 0x82);

    // Bitwise logic
    m.insert("OP_INVERT", 0x83);
    m.insert("OP_AND", 0x84);
    m.insert("OP_OR", 0x85);
    m.insert("OP_XOR", 0x86);
    m.insert("OP_EQUAL", 0x87);
    m.insert("OP_EQUALVERIFY", 0x88);

    // Arithmetic
    m.insert("OP_1ADD", 0x8b);
    m.insert("OP_1SUB", 0x8c);
    m.insert("OP_NEGATE", 0x8f);
    m.insert("OP_ABS", 0x90);
    m.insert("OP_NOT", 0x91);
    m.insert("OP_0NOTEQUAL", 0x92);
    m.insert("OP_ADD", 0x93);
    m.insert("OP_SUB", 0x94);
    m.insert("OP_MUL", 0x95);
    m.insert("OP_DIV", 0x96);
    m.insert("OP_MOD", 0x97);
    m.insert("OP_LSHIFT", 0x98);
    m.insert("OP_RSHIFT", 0x99);
    m.insert("OP_BOOLAND", 0x9a);
    m.insert("OP_BOOLOR", 0x9b);
    m.insert("OP_NUMEQUAL", 0x9c);
    m.insert("OP_NUMEQUALVERIFY", 0x9d);
    m.insert("OP_NUMNOTEQUAL", 0x9e);
    m.insert("OP_LESSTHAN", 0x9f);
    m.insert("OP_GREATERTHAN", 0xa0);
    m.insert("OP_LESSTHANOREQUAL", 0xa1);
    m.insert("OP_GREATERTHANOREQUAL", 0xa2);
    m.insert("OP_MIN", 0xa3);
    m.insert("OP_MAX", 0xa4);
    m.insert("OP_WITHIN", 0xa5);

    // Crypto
    m.insert("OP_RIPEMD160", 0xa6);
    m.insert("OP_SHA1", 0xa7);
    m.insert("OP_SHA256", 0xa8);
    m.insert("OP_HASH160", 0xa9);
    m.insert("OP_HASH256", 0xaa);
    m.insert("OP_CODESEPARATOR", 0xab);
    m.insert("OP_CHECKSIG", 0xac);
    m.insert("OP_CHECKSIGVERIFY", 0xad);
    m.insert("OP_CHECKMULTISIG", 0xae);
    m.insert("OP_CHECKMULTISIGVERIFY", 0xaf);

    // BSV Genesis protocol extensions
    m.insert("OP_REVERSE", 0xd1);

    m
});

/// Look up an opcode byte by name. Returns `None` if unknown.
pub fn opcode_byte(name: &str) -> Option<u8> {
    OPCODES.get(name).copied()
}
