//! State serialization and deserialization for stateful contracts.
//!
//! Stateful Rúnar contracts embed their state in the locking script as a
//! suffix of OP_RETURN-delimited raw bytes:
//!
//!   <code> OP_RETURN <field0> <field1> ... <fieldN>
//!
//! Each field is encoded as raw bytes (no push opcodes) matching the
//! compiler's OP_NUM2BIN-based fixed-width serialization:
//!   - int/bigint: 8 bytes LE sign-magnitude
//!   - bool: 1 byte (0x01 / 0x00)
//!   - PubKey: 33 raw bytes
//!   - Addr/Ripemd160: 20 raw bytes
//!   - Sha256: 32 raw bytes
//!   - Point: 64 raw bytes

use std::collections::HashMap;
use super::types::{StateField, RunarArtifact, SdkValue};

/// Serialize a set of state values into a hex-encoded raw byte section
/// (without the OP_RETURN prefix -- that is handled by the caller).
///
/// Field order is determined by the `index` property of each StateField.
pub fn serialize_state(
    fields: &[StateField],
    values: &HashMap<String, SdkValue>,
) -> String {
    let mut sorted: Vec<&StateField> = fields.iter().collect();
    sorted.sort_by_key(|f| f.index);

    let mut hex = String::new();
    for field in sorted {
        if let Some(value) = values.get(&field.name) {
            hex.push_str(&encode_state_value(value, &field.field_type));
        }
    }
    hex
}

/// Deserialize state values from a hex-encoded raw byte section.
///
/// The caller must strip the code prefix and OP_RETURN byte before passing
/// the data section.
pub fn deserialize_state(
    fields: &[StateField],
    script_hex: &str,
) -> HashMap<String, SdkValue> {
    let mut sorted: Vec<&StateField> = fields.iter().collect();
    sorted.sort_by_key(|f| f.index);

    let mut result = HashMap::new();
    let mut offset = 0;

    for field in sorted {
        let (value, bytes_read) = decode_state_value(script_hex, offset, &field.field_type);
        result.insert(field.name.clone(), value);
        offset += bytes_read;
    }

    result
}

/// Extract state from a full locking script hex, given the artifact.
///
/// Returns None if the artifact has no state fields or the script doesn't
/// contain a recognisable state section.
pub fn extract_state_from_script(
    artifact: &RunarArtifact,
    script_hex: &str,
) -> Option<HashMap<String, SdkValue>> {
    let state_fields = artifact.state_fields.as_ref()?;
    if state_fields.is_empty() {
        return None;
    }

    let last_op_return = find_last_op_return(script_hex)?;

    // State data starts after the OP_RETURN byte (2 hex chars)
    let state_hex = &script_hex[last_op_return + 2..];
    Some(deserialize_state(state_fields, state_hex))
}

/// Walk the script hex as Bitcoin Script opcodes to find the last OP_RETURN
/// (0x6a) at a real opcode boundary. Unlike `rfind("6a")`, this properly
/// skips push data so it won't match 0x6a bytes inside data payloads.
///
/// Returns the hex-char offset of the last OP_RETURN, or None.
pub fn find_last_op_return(script_hex: &str) -> Option<usize> {
    let mut offset = 0;
    let len = script_hex.len();

    while offset + 2 <= len {
        let opcode = u8::from_str_radix(&script_hex[offset..offset + 2], 16).unwrap_or(0);

        if opcode == 0x6a {
            // OP_RETURN at a real opcode boundary. Everything after is
            // raw state data (not opcodes), so stop walking immediately.
            return Some(offset);
        } else if opcode >= 0x01 && opcode <= 0x4b {
            // Direct push: opcode is the number of bytes
            offset += 2 + opcode as usize * 2;
        } else if opcode == 0x4c {
            // OP_PUSHDATA1: next 1 byte is the length
            if offset + 4 > len { break; }
            let push_len = u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
            offset += 4 + push_len * 2;
        } else if opcode == 0x4d {
            // OP_PUSHDATA2: next 2 bytes (LE) are the length
            if offset + 6 > len { break; }
            let lo = u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
            let hi = u8::from_str_radix(&script_hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
            let push_len = lo | (hi << 8);
            offset += 6 + push_len * 2;
        } else if opcode == 0x4e {
            // OP_PUSHDATA4: next 4 bytes (LE) are the length
            if offset + 10 > len { break; }
            let b0 = u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
            let b1 = u8::from_str_radix(&script_hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
            let b2 = u8::from_str_radix(&script_hex[offset + 6..offset + 8], 16).unwrap_or(0) as usize;
            let b3 = u8::from_str_radix(&script_hex[offset + 8..offset + 10], 16).unwrap_or(0) as usize;
            let push_len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            offset += 10 + push_len * 2;
        } else {
            // All other opcodes (OP_0, OP_1..16, OP_IF, OP_ADD, etc.)
            offset += 2;
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Encode a state field as raw bytes (no push opcode wrapper) matching the
/// compiler's OP_NUM2BIN-based fixed-width serialization.
fn encode_state_value(value: &SdkValue, field_type: &str) -> String {
    match field_type {
        "int" | "bigint" => {
            // Defensively handle SdkValue::Bytes containing a BigInt string
            // (e.g. "0n", "1000n") that may have slipped through from JSON
            // artifacts loaded without a BigInt reviver.
            let n = match value {
                SdkValue::Int(i) => *i,
                SdkValue::BigInt(bi) => {
                    // Convert BigInt to i64 for NUM2BIN encoding (state fields
                    // are always 8 bytes, so values must fit in i64 range).
                    bi.to_string().parse::<i64>().unwrap_or(0)
                }
                SdkValue::Bytes(s) => {
                    let num_str = if s.ends_with('n') { &s[..s.len() - 1] } else { s.as_str() };
                    num_str.parse::<i64>().unwrap_or(0)
                }
                _ => value.as_int(),
            };
            encode_num2bin(n, 8)
        }
        "bool" => {
            if value.as_bool() {
                "01".to_string()
            } else {
                "00".to_string()
            }
        }
        // All byte-like types: raw hex, no push opcode
        _ => {
            value.as_bytes().to_string()
        }
    }
}

/// Encode an integer as a fixed-width LE sign-magnitude byte string,
/// matching OP_NUM2BIN behaviour. The sign bit is in the MSB of the last byte.
fn encode_num2bin(n: i64, width: usize) -> String {
    let mut bytes = vec![0u8; width];
    let negative = n < 0;
    let mut abs_val = if negative { -(n as i128) } else { n as i128 } as u64;

    for i in 0..width {
        if abs_val == 0 { break; }
        bytes[i] = (abs_val & 0xff) as u8;
        abs_val >>= 8;
    }

    if negative {
        bytes[width - 1] |= 0x80;
    }

    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Wrap a hex-encoded byte string in a Bitcoin Script push data opcode.
pub(crate) fn encode_push_data(data_hex: &str) -> String {
    let len = data_hex.len() / 2;

    if len <= 75 {
        format!("{:02x}{}", len, data_hex)
    } else if len <= 0xff {
        format!("4c{:02x}{}", len, data_hex)
    } else if len <= 0xffff {
        format!("4d{}{}", to_little_endian_16(len), data_hex)
    } else {
        format!("4e{}{}", to_little_endian_32(len as u32), data_hex)
    }
}

fn to_little_endian_16(n: usize) -> String {
    format!("{:02x}{:02x}", n & 0xff, (n >> 8) & 0xff)
}

fn to_little_endian_32(n: u32) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        n & 0xff,
        (n >> 8) & 0xff,
        (n >> 16) & 0xff,
        (n >> 24) & 0xff,
    )
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

fn decode_state_value(
    hex: &str,
    offset: usize,
    field_type: &str,
) -> (SdkValue, usize) {
    match field_type {
        "bool" => {
            // 1 raw byte: 0x00 = false, 0x01 = true
            if offset + 2 > hex.len() {
                return (SdkValue::Bool(false), 2);
            }
            let byte = &hex[offset..offset + 2];
            (SdkValue::Bool(byte != "00"), 2)
        }
        "int" | "bigint" => {
            // 8 raw bytes LE sign-magnitude (NUM2BIN 8)
            let hex_width = 16; // 8 bytes * 2
            if offset + hex_width > hex.len() {
                return (SdkValue::Int(0), hex_width);
            }
            let data = &hex[offset..offset + hex_width];
            (SdkValue::Int(decode_num2bin(data)), hex_width)
        }
        "PubKey" => {
            let w = 66; // 33 bytes
            let data = if offset + w <= hex.len() { &hex[offset..offset + w] } else { "" };
            (SdkValue::Bytes(data.to_string()), w)
        }
        "Addr" | "Ripemd160" => {
            let w = 40; // 20 bytes
            let data = if offset + w <= hex.len() { &hex[offset..offset + w] } else { "" };
            (SdkValue::Bytes(data.to_string()), w)
        }
        "Sha256" => {
            let w = 64; // 32 bytes
            let data = if offset + w <= hex.len() { &hex[offset..offset + w] } else { "" };
            (SdkValue::Bytes(data.to_string()), w)
        }
        "Point" => {
            let w = 128; // 64 bytes
            let data = if offset + w <= hex.len() { &hex[offset..offset + w] } else { "" };
            (SdkValue::Bytes(data.to_string()), w)
        }
        _ => {
            // Unknown type: fall back to push-data decoding
            let (data, bytes_read) = decode_push_data(hex, offset);
            (SdkValue::Bytes(data), bytes_read)
        }
    }
}

/// Decode a fixed-width LE sign-magnitude number from hex.
fn decode_num2bin(hex: &str) -> i64 {
    if hex.is_empty() {
        return 0;
    }

    let mut bytes = Vec::new();
    let mut i = 0;
    while i + 2 <= hex.len() {
        bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0));
        i += 2;
    }

    let negative = (bytes[bytes.len() - 1] & 0x80) != 0;
    let last = bytes.len() - 1;
    bytes[last] &= 0x7f;

    let mut result: i64 = 0;
    for i in (0..bytes.len()).rev() {
        result = (result << 8) | (bytes[i] as i64);
    }

    if result == 0 { return 0; }
    if negative { -result } else { result }
}

/// Decode a Bitcoin Script push data at the given hex offset.
/// Returns the pushed data (hex) and the total number of hex chars consumed.
pub(crate) fn decode_push_data(hex: &str, offset: usize) -> (String, usize) {
    if offset + 2 > hex.len() {
        return (String::new(), 2);
    }

    let opcode = u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap_or(0);

    if opcode <= 75 {
        let data_len = opcode as usize * 2;
        let data = if offset + 2 + data_len <= hex.len() {
            hex[offset + 2..offset + 2 + data_len].to_string()
        } else {
            String::new()
        };
        (data, 2 + data_len)
    } else if opcode == 0x4c {
        // OP_PUSHDATA1
        let len = u8::from_str_radix(&hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let data_len = len * 2;
        let data = if offset + 4 + data_len <= hex.len() {
            hex[offset + 4..offset + 4 + data_len].to_string()
        } else {
            String::new()
        };
        (data, 4 + data_len)
    } else if opcode == 0x4d {
        // OP_PUSHDATA2
        let lo = u8::from_str_radix(&hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let hi = u8::from_str_radix(&hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
        let len = lo | (hi << 8);
        let data_len = len * 2;
        let data = if offset + 6 + data_len <= hex.len() {
            hex[offset + 6..offset + 6 + data_len].to_string()
        } else {
            String::new()
        };
        (data, 6 + data_len)
    } else if opcode == 0x4e {
        // OP_PUSHDATA4
        let b0 = u8::from_str_radix(&hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let b1 = u8::from_str_radix(&hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
        let b2 = u8::from_str_radix(&hex[offset + 6..offset + 8], 16).unwrap_or(0) as usize;
        let b3 = u8::from_str_radix(&hex[offset + 8..offset + 10], 16).unwrap_or(0) as usize;
        let len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        let data_len = len * 2;
        let data = if offset + 10 + data_len <= hex.len() {
            hex[offset + 10..offset + 10 + data_len].to_string()
        } else {
            String::new()
        };
        (data, 10 + data_len)
    } else {
        // Unknown opcode -- treat as zero-length
        (String::new(), 2)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fields(defs: &[(&str, &str, usize)]) -> Vec<StateField> {
        defs.iter()
            .map(|(name, typ, index)| StateField {
                name: name.to_string(),
                field_type: typ.to_string(),
                index: *index,
                initial_value: None,
            })
            .collect()
    }

    fn make_values(pairs: &[(&str, SdkValue)]) -> HashMap<String, SdkValue> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    // -----------------------------------------------------------------------
    // serialize_state / deserialize_state roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrips_single_bigint() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let values = make_values(&[("count", SdkValue::Int(42))]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["count"], SdkValue::Int(42));
    }

    #[test]
    fn roundtrips_zero_bigint() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let values = make_values(&[("count", SdkValue::Int(0))]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["count"], SdkValue::Int(0));
    }

    #[test]
    fn roundtrips_negative_bigint() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let values = make_values(&[("count", SdkValue::Int(-42))]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["count"], SdkValue::Int(-42));
    }

    #[test]
    fn roundtrips_large_bigint() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let values = make_values(&[("count", SdkValue::Int(1_000_000_000_000))]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["count"], SdkValue::Int(1_000_000_000_000));
    }

    #[test]
    fn roundtrips_multiple_fields() {
        let fields = make_fields(&[("a", "bigint", 0), ("b", "bigint", 1), ("c", "bigint", 2)]);
        let values = make_values(&[
            ("a", SdkValue::Int(1)),
            ("b", SdkValue::Int(2)),
            ("c", SdkValue::Int(3)),
        ]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["a"], SdkValue::Int(1));
        assert_eq!(result["b"], SdkValue::Int(2));
        assert_eq!(result["c"], SdkValue::Int(3));
    }

    // -----------------------------------------------------------------------
    // NUM2BIN encoding specifics
    // -----------------------------------------------------------------------

    #[test]
    fn encodes_zero_as_8_null_bytes() {
        let fields = make_fields(&[("v", "bigint", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("v", SdkValue::Int(0))]));
        assert_eq!(hex, "0000000000000000"); // 8 zero bytes
    }

    #[test]
    fn encodes_42_as_8_bytes_le() {
        let fields = make_fields(&[("v", "bigint", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("v", SdkValue::Int(42))]));
        assert_eq!(hex, "2a00000000000000"); // 42 in LE, zero-padded to 8 bytes
    }

    #[test]
    fn encodes_1000_as_8_bytes_le() {
        let fields = make_fields(&[("v", "bigint", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("v", SdkValue::Int(1000))]));
        assert_eq!(hex, "e803000000000000"); // 1000 = 0x03e8 in LE
    }

    #[test]
    fn encodes_negative_42_with_sign_bit() {
        let fields = make_fields(&[("v", "bigint", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("v", SdkValue::Int(-42))]));
        assert_eq!(hex, "2a00000000000080"); // 42 LE + sign bit in last byte
    }

    // -----------------------------------------------------------------------
    // Boolean encoding
    // -----------------------------------------------------------------------

    #[test]
    fn encodes_bool_true() {
        let fields = make_fields(&[("flag", "bool", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("flag", SdkValue::Bool(true))]));
        assert_eq!(hex, "01");
    }

    #[test]
    fn encodes_bool_false() {
        let fields = make_fields(&[("flag", "bool", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("flag", SdkValue::Bool(false))]));
        assert_eq!(hex, "00");
    }

    #[test]
    fn roundtrips_bool_true() {
        let fields = make_fields(&[("flag", "bool", 0)]);
        let values = make_values(&[("flag", SdkValue::Bool(true))]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["flag"], SdkValue::Bool(true));
    }

    #[test]
    fn roundtrips_bool_false() {
        let fields = make_fields(&[("flag", "bool", 0)]);
        let values = make_values(&[("flag", SdkValue::Bool(false))]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["flag"], SdkValue::Bool(false));
    }

    // -----------------------------------------------------------------------
    // Bytes encoding (raw, no push opcode)
    // -----------------------------------------------------------------------

    #[test]
    fn encodes_pubkey_as_raw_hex() {
        let pubkey = "ff".repeat(33);
        let fields = make_fields(&[("pk", "PubKey", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("pk", SdkValue::Bytes(pubkey.clone()))]));
        assert_eq!(hex, pubkey); // raw hex, no push prefix
    }

    #[test]
    fn encodes_addr_as_raw_hex() {
        let addr = "aa".repeat(20);
        let fields = make_fields(&[("a", "Addr", 0)]);
        let hex = serialize_state(&fields, &make_values(&[("a", SdkValue::Bytes(addr.clone()))]));
        assert_eq!(hex, addr); // raw hex, no push prefix
    }

    // -----------------------------------------------------------------------
    // Mixed fields
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrips_bigint_and_bool() {
        let fields = make_fields(&[("count", "bigint", 0), ("active", "bool", 1)]);
        let values = make_values(&[
            ("count", SdkValue::Int(100)),
            ("active", SdkValue::Bool(true)),
        ]);
        let hex = serialize_state(&fields, &values);
        let result = deserialize_state(&fields, &hex);
        assert_eq!(result["count"], SdkValue::Int(100));
        assert_eq!(result["active"], SdkValue::Bool(true));
    }

    // -----------------------------------------------------------------------
    // Bigint value roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrips_various_bigints() {
        let test_cases: &[(&str, i64)] = &[
            ("0", 0),
            ("1", 1),
            ("-1", -1),
            ("127", 127),
            ("128", 128),
            ("-128", -128),
            ("255", 255),
            ("256", 256),
            ("-256", -256),
            ("large_pos", 9_999_999_999),
            ("large_neg", -9_999_999_999),
        ];
        for (_label, value) in test_cases {
            let fields = make_fields(&[("v", "bigint", 0)]);
            let values = make_values(&[("v", SdkValue::Int(*value))]);
            let hex = serialize_state(&fields, &values);
            let result = deserialize_state(&fields, &hex);
            assert_eq!(result["v"], SdkValue::Int(*value), "failed for value {}", value);
        }
    }

    // -----------------------------------------------------------------------
    // extract_state_from_script
    // -----------------------------------------------------------------------

    #[test]
    fn extract_state_returns_none_no_state_fields() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "76a988ac".to_string(),
            state_fields: None,
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };
        let result = extract_state_from_script(&artifact, "76a988ac");
        assert!(result.is_none());
    }

    #[test]
    fn extract_state_returns_none_empty_state_fields() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };
        let result = extract_state_from_script(&artifact, "51");
        assert!(result.is_none());
    }

    #[test]
    fn extract_state_returns_none_no_op_return() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(fields),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };
        // Script with no 0x6a anywhere
        let result = extract_state_from_script(&artifact, "5193885187");
        assert!(result.is_none());
    }

    #[test]
    fn extract_state_finds_last_op_return() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let state_hex = serialize_state(
            &fields,
            &make_values(&[("count", SdkValue::Int(42))]),
        );
        // Code with embedded 0x6a, then real OP_RETURN, then state
        let code_with_embedded_6a = "016a93"; // PUSH(0x6a) OP_ADD
        let full_script = format!("{}6a{}", code_with_embedded_6a, state_hex);

        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(fields),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let result = extract_state_from_script(&artifact, &full_script);
        assert!(result.is_some());
        assert_eq!(result.unwrap()["count"], SdkValue::Int(42));
    }

    #[test]
    fn roundtrip_via_extract_state() {
        let fields = make_fields(&[
            ("count", "bigint", 0),
            ("owner", "PubKey", 1),
            ("active", "bool", 2),
        ]);
        let pubkey = "ab".repeat(33);
        let values = make_values(&[
            ("count", SdkValue::Int(7)),
            ("owner", SdkValue::Bytes(pubkey.clone())),
            ("active", SdkValue::Bool(true)),
        ]);
        let state_hex = serialize_state(&fields, &values);
        let full_script = format!("51{}{}", "6a", state_hex);

        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(fields),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let result = extract_state_from_script(&artifact, &full_script).unwrap();
        assert_eq!(result["count"], SdkValue::Int(7));
        assert_eq!(result["owner"], SdkValue::Bytes(pubkey));
        assert_eq!(result["active"], SdkValue::Bool(true));
    }

    #[test]
    fn field_ordering_by_index_regardless_of_declaration() {
        // Declare fields out of order (index 1 before index 0)
        let fields = make_fields(&[("b", "bigint", 1), ("a", "bigint", 0)]);
        let values = make_values(&[("a", SdkValue::Int(10)), ("b", SdkValue::Int(20))]);
        let state_hex = serialize_state(&fields, &values);
        let full_script = format!("ac6a{}", state_hex);

        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "ac".to_string(),
            state_fields: Some(fields),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let result = extract_state_from_script(&artifact, &full_script).unwrap();
        assert_eq!(result["a"], SdkValue::Int(10));
        assert_eq!(result["b"], SdkValue::Int(20));
    }

    // -------------------------------------------------------------------
    // find_last_op_return
    // -------------------------------------------------------------------

    #[test]
    fn find_op_return_simple() {
        // OP_1 OP_RETURN push(1 byte 0x2a)
        assert_eq!(find_last_op_return("516a012a"), Some(2));
    }

    #[test]
    fn find_op_return_skips_push_data() {
        // push(1 byte: 0x6a) OP_ADD OP_RETURN push(1 byte: 0x2a)
        assert_eq!(find_last_op_return("016a936a012a"), Some(6));
    }

    #[test]
    fn find_op_return_returns_none() {
        assert_eq!(find_last_op_return("5193885187"), None);
    }

    // -------------------------------------------------------------------
    // Defensive BigInt string handling in state serialization
    // -------------------------------------------------------------------

    #[test]
    fn bigint_serialize_state_handles_0n_string_defensively() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        // Simulate state containing unrevived "0n" string as SdkValue::Bytes
        let values = make_values(&[("count", SdkValue::Bytes("0n".to_string()))]);
        let hex = serialize_state(&fields, &values);
        assert_eq!(hex, "0000000000000000");
    }

    #[test]
    fn bigint_serialize_state_handles_1000n_string_defensively() {
        let fields = make_fields(&[("count", "bigint", 0)]);
        let values_str = make_values(&[("count", SdkValue::Bytes("1000n".to_string()))]);
        let hex_str = serialize_state(&fields, &values_str);
        // Should match the output from a proper SdkValue::Int(1000)
        let values_int = make_values(&[("count", SdkValue::Int(1000))]);
        let hex_int = serialize_state(&fields, &values_int);
        assert_eq!(hex_str, hex_int);
    }
}
