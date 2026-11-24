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
    m.insert("OP_2MUL", 0x8d);
    m.insert("OP_2DIV", 0x8e);
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

    // Chronicle opcodes
    m.insert("OP_SUBSTR", 0xb3);
    m.insert("OP_LEFT", 0xb4);
    m.insert("OP_RIGHT", 0xb5);
    m.insert("OP_LSHIFTNUM", 0xb6);
    m.insert("OP_RSHIFTNUM", 0xb7);

    m
});

/// Look up an opcode byte by name. Returns `None` if unknown.
pub fn opcode_byte(name: &str) -> Option<u8> {
    OPCODES.get(name).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_opcode_bytes() {
        let map = &*OPCODES;
        // Flow control
        assert_eq!(map.get("OP_IF"), Some(&0x63u8));
        assert_eq!(map.get("OP_ELSE"), Some(&0x67u8));
        assert_eq!(map.get("OP_ENDIF"), Some(&0x68u8));
        assert_eq!(map.get("OP_VERIFY"), Some(&0x69u8));
        assert_eq!(map.get("OP_RETURN"), Some(&0x6au8));

        // Stack
        assert_eq!(map.get("OP_TOALTSTACK"), Some(&0x6bu8));
        assert_eq!(map.get("OP_FROMALTSTACK"), Some(&0x6cu8));
        assert_eq!(map.get("OP_DROP"), Some(&0x75u8));
        assert_eq!(map.get("OP_DUP"), Some(&0x76u8));
        assert_eq!(map.get("OP_NIP"), Some(&0x77u8));
        assert_eq!(map.get("OP_OVER"), Some(&0x78u8));
        assert_eq!(map.get("OP_PICK"), Some(&0x79u8));
        assert_eq!(map.get("OP_ROLL"), Some(&0x7au8));
        assert_eq!(map.get("OP_ROT"), Some(&0x7bu8));
        assert_eq!(map.get("OP_SWAP"), Some(&0x7cu8));

        // Splice
        assert_eq!(map.get("OP_CAT"), Some(&0x7eu8));
        assert_eq!(map.get("OP_SPLIT"), Some(&0x7fu8));
        assert_eq!(map.get("OP_SIZE"), Some(&0x82u8));

        // Bitwise
        assert_eq!(map.get("OP_INVERT"), Some(&0x83u8));
        assert_eq!(map.get("OP_AND"), Some(&0x84u8));
        assert_eq!(map.get("OP_OR"), Some(&0x85u8));
        assert_eq!(map.get("OP_XOR"), Some(&0x86u8));
        assert_eq!(map.get("OP_EQUAL"), Some(&0x87u8));
        assert_eq!(map.get("OP_EQUALVERIFY"), Some(&0x88u8));

        // Arithmetic
        assert_eq!(map.get("OP_NOT"), Some(&0x91u8));
        assert_eq!(map.get("OP_ADD"), Some(&0x93u8));
        assert_eq!(map.get("OP_SUB"), Some(&0x94u8));
        assert_eq!(map.get("OP_MUL"), Some(&0x95u8));
        assert_eq!(map.get("OP_DIV"), Some(&0x96u8));
        assert_eq!(map.get("OP_MOD"), Some(&0x97u8));
        assert_eq!(map.get("OP_LSHIFT"), Some(&0x98u8));
        assert_eq!(map.get("OP_RSHIFT"), Some(&0x99u8));
        assert_eq!(map.get("OP_NUMEQUAL"), Some(&0x9cu8));
        assert_eq!(map.get("OP_NUMEQUALVERIFY"), Some(&0x9du8));
        assert_eq!(map.get("OP_LESSTHAN"), Some(&0x9fu8));
        assert_eq!(map.get("OP_GREATERTHAN"), Some(&0xa0u8));

        // Crypto
        assert_eq!(map.get("OP_RIPEMD160"), Some(&0xa6u8));
        assert_eq!(map.get("OP_SHA256"), Some(&0xa8u8));
        assert_eq!(map.get("OP_HASH160"), Some(&0xa9u8));
        assert_eq!(map.get("OP_HASH256"), Some(&0xaau8));
        assert_eq!(map.get("OP_CODESEPARATOR"), Some(&0xabu8));
        assert_eq!(map.get("OP_CHECKSIG"), Some(&0xacu8));
        assert_eq!(map.get("OP_CHECKSIGVERIFY"), Some(&0xadu8));
        assert_eq!(map.get("OP_CHECKMULTISIG"), Some(&0xaeu8));

        // Constants
        assert_eq!(map.get("OP_0"), Some(&0x00u8));
        assert_eq!(map.get("OP_FALSE"), Some(&0x00u8));
        assert_eq!(map.get("OP_1NEGATE"), Some(&0x4fu8));
        assert_eq!(map.get("OP_1"), Some(&0x51u8));
        assert_eq!(map.get("OP_TRUE"), Some(&0x51u8));
    }

    #[test]
    fn test_push_number_opcodes_sequential() {
        let map = &*OPCODES;
        for i in 1u8..=16 {
            let name = format!("OP_{i}");
            let expected = 0x50 + i;
            assert_eq!(
                map.get(name.as_str()),
                Some(&expected),
                "{name} should be 0x{expected:02x}"
            );
        }
    }
}
