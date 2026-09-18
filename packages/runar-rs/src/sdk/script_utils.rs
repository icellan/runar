//! Script utilities — constructor arg extraction, artifact matching, and
//! enhanced P2PKH script building.

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use super::types::{RunarArtifact, SdkValue};
use super::state::find_last_op_return;

// ---------------------------------------------------------------------------
// P2PKH script building (enhanced)
// ---------------------------------------------------------------------------

/// Build a standard P2PKH locking script hex from an address, pubkey hash,
/// or public key.
///
///   OP_DUP OP_HASH160 OP_PUSH20 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
///   76      a9         14        <20 bytes>    88              ac
///
/// Accepted input formats:
/// - 40-char hex: treated as raw 20-byte pubkey hash (hash160)
/// - 66-char hex: compressed public key (auto-hashed via hash160)
/// - 130-char hex: uncompressed public key (auto-hashed via hash160)
/// - Other: decoded as Base58Check BSV address
pub fn build_p2pkh_script(address_or_pub_key: &str) -> String {
    let pub_key_hash = if is_hex(address_or_pub_key, 40) {
        // Already a raw 20-byte pubkey hash in hex
        address_or_pub_key.to_string()
    } else if is_hex(address_or_pub_key, 66) || is_hex(address_or_pub_key, 130) {
        // Compressed (33 bytes) or uncompressed (65 bytes) public key — hash it
        let pub_key_bytes = hex_to_bytes(address_or_pub_key);
        let hash160 = compute_hash160(&pub_key_bytes);
        bytes_to_hex(&hash160)
    } else {
        // Decode Base58Check address to extract the 20-byte pubkey hash
        let decoded = bs58::decode(address_or_pub_key)
            .with_check(None)
            .into_vec()
            .unwrap_or_else(|e| panic!("build_p2pkh_script: invalid address {:?}: {}", address_or_pub_key, e));
        if decoded.len() != 21 {
            panic!(
                "build_p2pkh_script: unexpected decoded length {} for {:?}",
                decoded.len(), address_or_pub_key
            );
        }
        // Skip version byte (0x00 for mainnet, 0x6f for testnet), take 20-byte hash
        bytes_to_hex(&decoded[1..])
    };

    format!("76a914{}88ac", pub_key_hash)
}

// ---------------------------------------------------------------------------
// Constructor arg extraction
// ---------------------------------------------------------------------------

/// Read a single Bitcoin Script element (opcode + data) at the given hex offset.
///
/// Returns the pushed data hex, total hex chars consumed, and the opcode byte.
fn read_script_element(hex: &str, offset: usize) -> (String, usize, u8) {
    if offset + 2 > hex.len() {
        return (String::new(), 2, 0);
    }
    let opcode = u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap_or(0);

    if opcode == 0x00 {
        return (String::new(), 2, opcode);
    }
    if opcode >= 0x01 && opcode <= 0x4b {
        let data_len = opcode as usize * 2;
        let data = safe_slice(hex, offset + 2, data_len);
        return (data, 2 + data_len, opcode);
    }
    if opcode == 0x4c {
        // OP_PUSHDATA1
        if offset + 4 > hex.len() { return (String::new(), 2, opcode); }
        let len = u8::from_str_radix(&hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let data_len = len * 2;
        let data = safe_slice(hex, offset + 4, data_len);
        return (data, 4 + data_len, opcode);
    }
    if opcode == 0x4d {
        // OP_PUSHDATA2
        if offset + 6 > hex.len() { return (String::new(), 2, opcode); }
        let lo = u8::from_str_radix(&hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let hi = u8::from_str_radix(&hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
        let len = lo | (hi << 8);
        let data_len = len * 2;
        let data = safe_slice(hex, offset + 6, data_len);
        return (data, 6 + data_len, opcode);
    }
    if opcode == 0x4e {
        // OP_PUSHDATA4
        if offset + 10 > hex.len() { return (String::new(), 2, opcode); }
        let b0 = u8::from_str_radix(&hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let b1 = u8::from_str_radix(&hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
        let b2 = u8::from_str_radix(&hex[offset + 6..offset + 8], 16).unwrap_or(0) as usize;
        let b3 = u8::from_str_radix(&hex[offset + 8..offset + 10], 16).unwrap_or(0) as usize;
        let len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        let data_len = len * 2;
        let data = safe_slice(hex, offset + 10, data_len);
        return (data, 10 + data_len, opcode);
    }

    // All other opcodes
    (String::new(), 2, opcode)
}

/// Safely slice a hex string, returning empty if out of bounds.
fn safe_slice(hex: &str, start: usize, len: usize) -> String {
    if start + len <= hex.len() {
        hex[start..start + len].to_string()
    } else {
        String::new()
    }
}

/// Decode a Bitcoin Script number from hex (little-endian sign-magnitude).
///
/// N-074: a Script number is ARBITRARY PRECISION — Rúnar contracts routinely
/// carry 256-bit EC scalars and 1024-bit+ Rabin moduli as plain `bigint`
/// constructor args. Accumulating into an `i64` wrapped SILENTLY at 9 data
/// bytes (`|v| >= 2^63`; `<<` traps only on an out-of-range shift AMOUNT, never
/// on value overflow), so those values came back wrong and rebuilt a locking
/// script that no longer matched chain. The encode side
/// (`contract::encode_bigint_script_number`) was already arbitrary-precision;
/// the asymmetry was the bug.
fn decode_script_number(data_hex: &str) -> num_bigint::BigInt {
    use num_bigint::{BigInt, Sign};

    if data_hex.is_empty() {
        return BigInt::from(0);
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    while i + 2 <= data_hex.len() {
        bytes.push(u8::from_str_radix(&data_hex[i..i + 2], 16).unwrap_or(0));
        i += 2;
    }
    if bytes.is_empty() {
        return BigInt::from(0);
    }

    let last = bytes.len() - 1;
    let negative = (bytes[last] & 0x80) != 0;
    bytes[last] &= 0x7f;

    // Sign-magnitude, little-endian: the magnitude is the byte string itself.
    let magnitude = BigInt::from_bytes_le(Sign::Plus, &bytes);
    if magnitude.sign() == Sign::NoSign {
        return BigInt::from(0);
    }
    if negative { -magnitude } else { magnitude }
}

/// Narrow a decoded Script number back to `SdkValue::Int` whenever it fits, so
/// every existing caller that matches on `Int` keeps working; only values that
/// genuinely cannot be represented surface as `SdkValue::BigInt` (which
/// `contract::encode_arg` already handles).
fn script_number_value(n: num_bigint::BigInt) -> SdkValue {
    match i64::try_from(&n) {
        Ok(small) => SdkValue::Int(small),
        Err(_) => SdkValue::BigInt(n),
    }
}

/// Interpret a script element according to the expected ABI type.
/// How a constructor-slot value of the given ABI type is encoded in the script.
///
/// TABLE, not a `match` arm list: the two spellings missing from the old match
/// — the `bigint` aliases `RabinSig` / `RabinPubKey`, and the CANONICAL
/// `boolean` (only the `bool` alias was matched) — each silently turned a value
/// into a hex string on the way back off chain. Mirrors
/// `packages/runar-ir-schema/src/abi-type-encoding.ts`, the same table the
/// compiler stamps `ConstructorSlot.valueEncoding` from.
const ABI_VALUE_ENCODINGS: &[(&str, AbiValueEncoding)] = &[
    ("bigint", AbiValueEncoding::ScriptNum),
    ("int", AbiValueEncoding::ScriptNum),
    // RabinSig / RabinPubKey are bigint aliases; `verifyRabinSig` lowers to
    // OP_MOD, which reads its operand as a little-endian sign-magnitude Script
    // number — exactly what `bigint` gets.
    ("RabinSig", AbiValueEncoding::ScriptNum),
    ("RabinPubKey", AbiValueEncoding::ScriptNum),
    // `boolean` is canonical; `bool` is the alias several frontends spell.
    ("boolean", AbiValueEncoding::Bool),
    ("bool", AbiValueEncoding::Bool),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum AbiValueEncoding {
    ScriptNum,
    Bool,
    /// ByteString and every fixed-width byte type: a raw data push.
    Data,
}

fn abi_value_encoding(param_type: &str) -> AbiValueEncoding {
    ABI_VALUE_ENCODINGS
        .iter()
        .find(|(name, _)| *name == param_type)
        .map(|(_, enc)| *enc)
        .unwrap_or(AbiValueEncoding::Data)
}

fn interpret_script_element(opcode: u8, data_hex: &str, param_type: &str) -> SdkValue {
    match abi_value_encoding(param_type) {
        AbiValueEncoding::ScriptNum => {
            if opcode == 0x00 {
                return SdkValue::Int(0);
            }
            if opcode >= 0x51 && opcode <= 0x60 {
                return SdkValue::Int((opcode as i64) - 0x50);
            }
            if opcode == 0x4f {
                return SdkValue::Int(-1);
            }
            script_number_value(decode_script_number(data_hex))
        }
        AbiValueEncoding::Bool => {
            if opcode == 0x00 {
                return SdkValue::Bool(false);
            }
            if opcode == 0x51 {
                return SdkValue::Bool(true);
            }
            SdkValue::Bool(data_hex != "00")
        }
        AbiValueEncoding::Data => {
            // S1: a ByteString (or other non-numeric) ctor arg whose 1-byte
            // value was MINIMALDATA-encoded as OP_1..OP_16 / OP_1NEGATE
            // carries no separate data bytes in the script —
            // `read_script_element` reports an empty `data_hex` for these
            // opcodes (they are neither direct pushes nor OP_PUSHDATA*). The
            // opcode itself IS the value; reconstruct it instead of
            // forwarding the (empty) data_hex. OP_0 correctly falls through
            // to `data_hex` (the empty string), matching OP_0's true
            // semantics (pushes `[]`, not a 1-byte `0x00`).
            if (0x51..=0x60).contains(&opcode) {
                return SdkValue::Bytes(format!("{:02x}", opcode - 0x50));
            }
            if opcode == 0x4f {
                return SdkValue::Bytes("81".to_string());
            }
            SdkValue::Bytes(data_hex.to_string())
        }
    }
}

/// Extract constructor argument values from a compiled on-chain script.
///
/// Uses `artifact.constructorSlots` to locate each constructor arg at its
/// byte offset, reads the push data, and deserializes according to the
/// ABI param type.
pub fn extract_constructor_args(
    artifact: &RunarArtifact,
    script_hex: &str,
) -> Result<HashMap<String, SdkValue>, String> {
    let slots = match artifact.constructor_slots.as_ref() {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(HashMap::new()),
    };

    let mut code_hex = script_hex.to_string();
    if let Some(ref state_fields) = artifact.state_fields {
        if !state_fields.is_empty() {
            if let Some(op_return_pos) = find_last_op_return(script_hex) {
                code_hex = script_hex[..op_return_pos].to_string();
            }
        }
    }

    // Walk EVERY slot in byte order. A constructor param referenced more than
    // once in the contract body emits one slot per reference, and each
    // occurrence's encoded width contributes to the cumulative offset shift —
    // deduplicating before the walk drops those widths and mis-aligns every
    // later slot on artifacts with repeated references. The VALUE is taken
    // from the first occurrence per param.
    let mut sorted_slots: Vec<_> = slots.iter().collect();
    sorted_slots.sort_by_key(|s| s.byte_offset);

    let mut result = HashMap::new();
    let mut assigned = std::collections::HashSet::new();
    let mut cumulative_shift: isize = 0;

    for slot in &sorted_slots {
        let adjusted_hex_offset = ((slot.byte_offset as isize) + cumulative_shift) as usize * 2;
        let (data_hex, total_hex_chars, opcode) = read_script_element(&code_hex, adjusted_hex_offset);
        // Template placeholders are exactly 1 byte, so the shift contributed by
        // each occurrence is its encoded width minus that byte.
        cumulative_shift += (total_hex_chars as isize) / 2 - 1;

        if !assigned.insert(slot.param_index) {
            continue;
        }
        if slot.param_index < artifact.abi.constructor.params.len() {
            let param = &artifact.abi.constructor.params[slot.param_index];
            let value = interpret_script_element(opcode, &data_hex, &param.param_type);
            result.insert(param.name.clone(), value);
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Script matching
// ---------------------------------------------------------------------------

/// Determine whether a given on-chain script was produced from the given
/// contract artifact (regardless of what constructor args were used).
pub fn matches_artifact(artifact: &RunarArtifact, script_hex: &str) -> bool {
    let mut code_hex = script_hex.to_string();
    if let Some(ref state_fields) = artifact.state_fields {
        if !state_fields.is_empty() {
            if let Some(op_return_pos) = find_last_op_return(script_hex) {
                code_hex = script_hex[..op_return_pos].to_string();
            }
        }
    }

    let template = &artifact.script;

    let slots = match artifact.constructor_slots.as_ref() {
        Some(s) if !s.is_empty() => s,
        _ => return code_hex == *template,
    };

    // Deduplicate by byteOffset and sort
    let mut seen_offsets = std::collections::HashSet::new();
    let mut sorted_slots: Vec<_> = slots.iter().collect();
    sorted_slots.sort_by_key(|s| s.byte_offset);
    sorted_slots.retain(|s| seen_offsets.insert(s.byte_offset));

    let mut template_pos = 0;
    let mut code_pos = 0;

    for slot in &sorted_slots {
        let slot_hex_offset = slot.byte_offset * 2;
        let template_segment = &template[template_pos..slot_hex_offset];
        let code_end = code_pos + template_segment.len();
        if code_end > code_hex.len() {
            return false;
        }
        let code_segment = &code_hex[code_pos..code_end];
        if template_segment != code_segment {
            return false;
        }
        template_pos = slot_hex_offset + 2;
        let elem_offset = code_pos + template_segment.len();
        let (_, total_hex_chars, _) = read_script_element(&code_hex, elem_offset);
        code_pos = elem_offset + total_hex_chars;
    }

    template[template_pos..] == code_hex[code_pos..]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn compute_hash160(data: &[u8]) -> Vec<u8> {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    ripe.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::types::{Abi, AbiConstructor, AbiMethod, AbiParam, ConstructorSlot};

    fn make_artifact(script: &str, constructor_params: Vec<AbiParam>, slots: Vec<ConstructorSlot>) -> RunarArtifact {
        RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "Test".to_string(),
            parent_class: None,
            abi: Abi {
                constructor: AbiConstructor { params: constructor_params },
                methods: vec![AbiMethod {
                    name: "spend".to_string(),
                    params: vec![],
                    is_public: true,
                    is_terminal: None, uses_code_part: None,
                    sig_hash_type: None,
                }],
            },
            script: script.to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: Some(slots),
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: None,
        }
    }

    // -----------------------------------------------------------------------
    // build_p2pkh_script
    // -----------------------------------------------------------------------

    #[test]
    fn build_p2pkh_from_hash160() {
        let hash = "00".repeat(20);
        let script = build_p2pkh_script(&hash);
        assert_eq!(script, format!("76a914{}88ac", hash));
    }

    #[test]
    fn build_p2pkh_from_compressed_pubkey() {
        // Known compressed pubkey for private key 1
        let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let script = build_p2pkh_script(pubkey);
        // Should produce a valid P2PKH script (76a914...88ac)
        assert!(script.starts_with("76a914"));
        assert!(script.ends_with("88ac"));
        assert_eq!(script.len(), 50); // 76a914 + 40 + 88ac = 6 + 40 + 4 = 50
    }

    #[test]
    fn build_p2pkh_from_uncompressed_pubkey() {
        let pubkey = format!("04{}", "ab".repeat(64));
        let script = build_p2pkh_script(&pubkey);
        assert!(script.starts_with("76a914"));
        assert!(script.ends_with("88ac"));
        assert_eq!(script.len(), 50);
    }

    // -----------------------------------------------------------------------
    // extract_constructor_args
    // -----------------------------------------------------------------------

    #[test]
    fn extract_args_empty_when_no_slots() {
        let artifact = RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "Test".to_string(),
            parent_class: None,
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: None,
        };
        let result = extract_constructor_args(&artifact, "51").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn extract_args_reads_bigint() {
        // Script: OP_PUSH(1 byte: 0x2a = 42) then OP_ADD
        // The constructor slot is at byte offset 0 (the push opcode location)
        let artifact = make_artifact(
            "0093", // placeholder + OP_ADD
            vec![AbiParam { name: "x".to_string(), param_type: "bigint".to_string(), fixed_array: None }],
            vec![ConstructorSlot { param_index: 0, byte_offset: 0 }],
        );
        // Actual script has push(1 byte: 42)
        let script = "012a93";
        let result = extract_constructor_args(&artifact, script).unwrap();
        assert_eq!(result["x"], SdkValue::Int(42));
    }

    #[test]
    fn extract_args_reads_bool_true() {
        let artifact = make_artifact(
            "0093",
            vec![AbiParam { name: "flag".to_string(), param_type: "bool".to_string(), fixed_array: None }],
            vec![ConstructorSlot { param_index: 0, byte_offset: 0 }],
        );
        // OP_1 (0x51) then OP_ADD
        let script = "5193";
        let result = extract_constructor_args(&artifact, script).unwrap();
        assert_eq!(result["flag"], SdkValue::Bool(true));
    }

    #[test]
    fn extract_args_reads_op_0_as_zero() {
        let artifact = make_artifact(
            "0093",
            vec![AbiParam { name: "x".to_string(), param_type: "bigint".to_string(), fixed_array: None }],
            vec![ConstructorSlot { param_index: 0, byte_offset: 0 }],
        );
        // OP_0 (0x00) then OP_ADD
        let script = "0093";
        let result = extract_constructor_args(&artifact, script).unwrap();
        assert_eq!(result["x"], SdkValue::Int(0));
    }

    #[test]
    fn extract_args_reads_op_1_through_16() {
        for n in 1u8..=16 {
            let opcode = 0x50 + n;
            let artifact = make_artifact(
                "0093",
                vec![AbiParam { name: "x".to_string(), param_type: "bigint".to_string(), fixed_array: None }],
                vec![ConstructorSlot { param_index: 0, byte_offset: 0 }],
            );
            let script = format!("{:02x}93", opcode);
            let result = extract_constructor_args(&artifact, &script).unwrap();
            assert_eq!(result["x"], SdkValue::Int(n as i64));
        }
    }

    #[test]
    fn extract_args_reads_bytes() {
        let artifact = make_artifact(
            "0093",
            vec![AbiParam { name: "pk".to_string(), param_type: "PubKey".to_string(), fixed_array: None }],
            vec![ConstructorSlot { param_index: 0, byte_offset: 0 }],
        );
        let pubkey_hex = "ab".repeat(33);
        let script = format!("21{}93", pubkey_hex); // PUSH(33 bytes)
        let result = extract_constructor_args(&artifact, &script).unwrap();
        assert_eq!(result["pk"], SdkValue::Bytes(pubkey_hex));
    }

    // -----------------------------------------------------------------------
    // extract_constructor_args — repeated constructor-slot references
    // -----------------------------------------------------------------------

    /// A param referenced N times in the contract body emits N constructor
    /// slots. Every occurrence's encoded width shifts the offsets of everything
    /// after it, so the extractor must account for ALL occurrences — not just
    /// the first per param. Regression for a bug where slots were deduplicated
    /// by param_index BEFORE the offset walk, mis-reading every later slot
    /// whenever an earlier repeated value encoded wider than its 1-byte
    /// template placeholder.
    ///
    /// Template: ab <00> 7c <00> 7c <00> ac
    ///   offset 1: alpha (param_index 0)
    ///   offset 3: alpha again (param_index 0 — second reference)
    ///   offset 5: beta  (param_index 1)
    fn repeated_slot_artifact() -> RunarArtifact {
        make_artifact(
            "ab007c007c00ac",
            vec![
                AbiParam { name: "alpha".to_string(), param_type: "bigint".to_string(), fixed_array: None },
                AbiParam { name: "beta".to_string(), param_type: "bigint".to_string(), fixed_array: None },
            ],
            vec![
                ConstructorSlot { param_index: 0, byte_offset: 1 },
                ConstructorSlot { param_index: 0, byte_offset: 3 },
                ConstructorSlot { param_index: 1, byte_offset: 5 },
            ],
        )
    }

    #[test]
    fn extract_args_reads_slots_after_repeated_wide_value() {
        // alpha = 500 (scriptnum push `02f401`, 3 bytes), beta = 7 (OP_7, 1 byte)
        let artifact = repeated_slot_artifact();
        let resolved = "ab02f4017c02f4017c57ac";
        let result = extract_constructor_args(&artifact, resolved).unwrap();
        assert_eq!(result["alpha"], SdkValue::Int(500));
        // Before the fix, the second alpha occurrence's +2 byte shift was
        // dropped, so beta was read from inside the second alpha push and
        // decoded as 124 instead of 7.
        assert_eq!(result["beta"], SdkValue::Int(7));
    }

    #[test]
    fn extract_args_repeated_value_fitting_placeholder_width() {
        // alpha = 5 → OP_5 (1 byte, same width as the placeholder: zero shift).
        let artifact = repeated_slot_artifact();
        let resolved = "ab557c557c57ac";
        let result = extract_constructor_args(&artifact, resolved).unwrap();
        assert_eq!(result["alpha"], SdkValue::Int(5));
        assert_eq!(result["beta"], SdkValue::Int(7));
    }

    // -----------------------------------------------------------------------
    // matches_artifact
    // -----------------------------------------------------------------------

    #[test]
    fn matches_artifact_no_slots() {
        let artifact = RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "Test".to_string(),
            parent_class: None,
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "5151".to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: None,
        };
        assert!(matches_artifact(&artifact, "5151"));
        assert!(!matches_artifact(&artifact, "5152"));
    }

    #[test]
    fn matches_artifact_with_slots_different_args() {
        // Template: placeholder(00) + OP_ADD(93)
        let artifact = make_artifact(
            "0093",
            vec![AbiParam { name: "x".to_string(), param_type: "bigint".to_string(), fixed_array: None }],
            vec![ConstructorSlot { param_index: 0, byte_offset: 0 }],
        );
        // Script with different arg (push 1 byte: 42) then OP_ADD
        assert!(matches_artifact(&artifact, "012a93"));
        // Script with arg=0 (OP_0) then OP_ADD
        assert!(matches_artifact(&artifact, "0093"));
        // Different suffix should not match
        assert!(!matches_artifact(&artifact, "012a94"));
    }

    #[test]
    fn matches_artifact_strips_state_data() {
        let artifact = RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "Test".to_string(),
            parent_class: None,
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "5151".to_string(),
            asm: None,
            state_fields: Some(vec![crate::sdk::types::StateField {
                name: "count".to_string(),
                field_type: "bigint".to_string(),
                index: 0,
                initial_value: None, fixed_array: None ,
            }]),
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: None,
        };
        // Script with code + OP_RETURN + state data
        assert!(matches_artifact(&artifact, "51516a0000000000000000"));
        // Without state should still match
        assert!(matches_artifact(&artifact, "5151"));
    }

// -----------------------------------------------------------------------
// N-070 (extract half) — `interpret_script_element` must know every ABI type
// spelling the compiler can emit.
//
// Two holes, identical in shape across all seven SDK tiers:
//
//   RabinSig / RabinPubKey — `bigint` ALIASES (runar-lang/src/types.ts:68-71)
//     that `verifyRabinSig` consumes with OP_MOD, i.e. as a Script NUMBER.
//     Absent from the match, so a restored contract's modulus came back as the
//     little-endian hex blob "1581e97df4102211" instead of the number. Feed
//     that back into a call and the rebuilt locking script no longer matches
//     what is on chain.
//
//   boolean — the CANONICAL Rúnar primitive name; only the alias `bool` was
//     matched. A boolean slot fell through to the byte arm, so `true` came
//     back as the string "01" and `false` as "". Java's ContractScript was the
//     only tier of seven that tested both spellings.
//
// NOTE ON WIDTH: `decode_script_number` returns i64, so this test uses a
// modulus that fits. A real 128-byte Rabin modulus does not — a pre-existing,
// type-INDEPENDENT limit of this tier's script-number decoder (it bites a plain
// `bigint` ctor arg of the same size identically), out of scope here.
// -----------------------------------------------------------------------

const N070_MODULUS: i64 = 1_234_567_890_123_456_789;
const N070_RABIN_PUSH: &str = "081581e97df4102211"; // minimal LE sign-magnitude
const N070_BLOB: &str = "04deadbeef";

/// Template: `<modulus@0> 7c <flag@2> 7c <blob@4> ac`
fn n070_artifact(rabin_type: &str, bool_type: &str) -> RunarArtifact {
    make_artifact(
        "007c007c00ac",
        vec![
            AbiParam { name: "modulus".into(), param_type: rabin_type.into(), fixed_array: None },
            AbiParam { name: "flag".into(), param_type: bool_type.into(), fixed_array: None },
            AbiParam { name: "blob".into(), param_type: "ByteString".into(), fixed_array: None },
        ],
        vec![
            ConstructorSlot { param_index: 0, byte_offset: 0 },
            ConstructorSlot { param_index: 1, byte_offset: 2 },
            ConstructorSlot { param_index: 2, byte_offset: 4 },
        ],
    )
}

fn n070_script(flag_opcode: &str) -> String {
    format!("{N070_RABIN_PUSH}7c{flag_opcode}7c{N070_BLOB}ac")
}

#[test]
fn n070_rabin_slots_extract_as_numbers() {
    for type_name in ["RabinPubKey", "RabinSig"] {
        let artifact = n070_artifact(type_name, "boolean");
        let args = extract_constructor_args(&artifact, &n070_script("51")).unwrap();
        assert_eq!(
            args.get("modulus"),
            Some(&SdkValue::Int(N070_MODULUS)),
            "{type_name}: modulus must extract as a script number, got {:?}",
            args.get("modulus")
        );
    }
}

#[test]
fn n070_canonical_boolean_slot_extracts_as_bool() {
    for (opcode, want) in [("51", true), ("00", false)] {
        let artifact = n070_artifact("RabinPubKey", "boolean");
        let args = extract_constructor_args(&artifact, &n070_script(opcode)).unwrap();
        assert_eq!(
            args.get("flag"),
            Some(&SdkValue::Bool(want)),
            "opcode {opcode}: got {:?}",
            args.get("flag")
        );
    }
}

#[test]
fn n070_boolean_and_bool_spellings_agree() {
    for opcode in ["51", "00"] {
        let canonical = extract_constructor_args(&n070_artifact("RabinPubKey", "boolean"), &n070_script(opcode)).unwrap();
        let alias = extract_constructor_args(&n070_artifact("RabinPubKey", "bool"), &n070_script(opcode)).unwrap();
        assert_eq!(canonical.get("flag"), alias.get("flag"), "opcode {opcode}");
    }
}

/// CONTROL: the classes that already worked must not move.
#[test]
fn n070_control_other_types_unchanged() {
    for type_name in ["bigint", "int"] {
        let args = extract_constructor_args(&n070_artifact(type_name, "bool"), &n070_script("51")).unwrap();
        assert_eq!(args.get("modulus"), Some(&SdkValue::Int(N070_MODULUS)), "{type_name}");
    }
    // A ByteString slot still comes back as its hex payload, NOT a number, and
    // the offset walk past the wide Rabin push still lands on it.
    let args = extract_constructor_args(&n070_artifact("RabinPubKey", "boolean"), &n070_script("51")).unwrap();
    assert_eq!(args.get("blob"), Some(&SdkValue::Bytes("deadbeef".to_string())));
    // S1: a 1-byte ByteString MINIMALDATA-encoded as OP_5 is still
    // reconstructed from the opcode.
    let s1 = extract_constructor_args(
        &n070_artifact("RabinPubKey", "boolean"),
        &format!("{N070_RABIN_PUSH}7c517c55ac"),
    )
    .unwrap();
    assert_eq!(s1.get("blob"), Some(&SdkValue::Bytes("05".to_string())));
}
}

// ---------------------------------------------------------------------------
// N-074 — a Bitcoin Script number is ARBITRARY PRECISION.
//
// Rúnar contracts routinely carry 256-bit EC scalars and 1024-bit+ Rabin
// moduli as plain `bigint` constructor args. `decode_script_number` returned
// i64, so every value past 2^63 came back silently WRONG (`<<` on an i64 does
// not trap on value overflow, only on an out-of-range shift AMOUNT) — and
// feeding that wrong value back into a call rebuilds a locking script that no
// longer matches what is on chain.
//
// This is type-INDEPENDENT: `bigint`, `int`, `RabinSig` and `RabinPubKey` all
// bite identically. Nothing about it is Rabin-specific.
//
// The ENCODE direction was already arbitrary-precision
// (`contract::encode_bigint_script_number`). The asymmetry WAS the bug, so
// every case below is a real encode -> decode round trip.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod n074_script_number_width {
    use super::*;
    use crate::sdk::contract::{encode_bigint_script_number, encode_script_number};
    use crate::sdk::types::{Abi, AbiConstructor, AbiParam, ConstructorSlot};
    use num_bigint::BigInt;
    use std::str::FromStr;

    /// secp256k1 group order — a real 256-bit EC scalar.
    const SECP_N: &str = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
    /// A deterministic 1024-bit odd modulus with the top bit set: the shape of
    /// a real Rabin public key (128 bytes).
    const RABIN_1024: &str = "99068719171432002146137311586819387646033673282442268174774782671999562801264502320230697368056122056037887996485526845789822730341467216601217971743412906058452632946239858722327898748234874221141359423697249054724716242045815478148675575955849558861539174810221469540865911313499616042524201320198581026695";

    fn magnitudes() -> Vec<(&'static str, BigInt)> {
        vec![
            ("small", BigInt::from(1234567890123456789i64)),
            ("2^63-1", BigInt::from_str("9223372036854775807").unwrap()),
            ("2^63", BigInt::from_str("9223372036854775808").unwrap()),
            ("2^64", BigInt::from_str("18446744073709551616").unwrap()),
            ("secp256k1 N (256-bit)", BigInt::from_str(SECP_N).unwrap()),
            ("Rabin modulus (1024-bit)", BigInt::from_str(RABIN_1024).unwrap()),
        ]
    }

    /// Single-slot template: `<value@0> ac`
    fn artifact(type_name: &str) -> RunarArtifact {
        RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "N074".to_string(),
            parent_class: None,
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam {
                        name: "value".to_string(),
                        param_type: type_name.to_string(),
                        fixed_array: None,
                    }],
                },
                methods: vec![],
            },
            script: "00ac".to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: Some(vec![ConstructorSlot { param_index: 0, byte_offset: 0 }]),
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: None,
        }
    }

    /// Run the real encode -> extract path, normalising whatever concrete
    /// `SdkValue` variant comes back into a `BigInt` for comparison.
    fn round_trip(type_name: &str, v: &BigInt) -> BigInt {
        let script = format!("{}ac", encode_bigint_script_number(v));
        let args = extract_constructor_args(&artifact(type_name), &script).unwrap();
        match args.get("value") {
            Some(SdkValue::BigInt(n)) => n.clone(),
            Some(SdkValue::Int(n)) => BigInt::from(*n),
            other => panic!("{type_name}: value extracted as {other:?}, want a script number"),
        }
    }

    #[test]
    fn positive_round_trip_at_every_magnitude() {
        for type_name in ["bigint", "int", "RabinPubKey", "RabinSig"] {
            for (name, v) in magnitudes() {
                assert_eq!(round_trip(type_name, &v), v, "{type_name} / {name}");
            }
        }
    }

    /// Bitcoin script numbers are SIGN-MAGNITUDE, not two's complement: the
    /// sign lives in the high bit of the most-significant byte. This is where a
    /// naive bignum port breaks.
    #[test]
    fn negative_round_trip_at_every_magnitude() {
        for type_name in ["bigint", "RabinPubKey"] {
            for (name, v) in magnitudes() {
                let neg = -v;
                assert_eq!(round_trip(type_name, &neg), neg, "{type_name} / -{name}");
            }
        }
    }

    /// CONTROL: small values stay byte-identical on the wire AND keep their
    /// existing `SdkValue::Int` variant, so no caller that matches on it breaks.
    #[test]
    fn control_small_values_unchanged() {
        let cases: &[(i64, &str)] = &[
            (0, "00"),
            (1, "51"),
            (16, "60"),
            (-1, "4f"),
            (17, "0111"),
            (127, "017f"),
            (128, "028000"),
            (-128, "028080"),
            (1234567890123456789, "081581e97df4102211"),
            (-1234567890123456789, "081581e97df4102291"),
        ];
        for (v, want) in cases {
            assert_eq!(&encode_script_number(*v), want, "encode {v}");
            assert_eq!(
                &encode_bigint_script_number(&BigInt::from(*v)),
                want,
                "encode_bigint {v}"
            );
            let args = extract_constructor_args(&artifact("bigint"), &format!("{want}ac")).unwrap();
            assert_eq!(args.get("value"), Some(&SdkValue::Int(*v)), "extract {v}");
        }
    }
}
