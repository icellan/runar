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
fn decode_script_number(data_hex: &str) -> i64 {
    if data_hex.is_empty() {
        return 0;
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    while i + 2 <= data_hex.len() {
        bytes.push(u8::from_str_radix(&data_hex[i..i + 2], 16).unwrap_or(0));
        i += 2;
    }
    if bytes.is_empty() {
        return 0;
    }

    let last = bytes.len() - 1;
    let negative = (bytes[last] & 0x80) != 0;
    bytes[last] &= 0x7f;

    let mut result: i64 = 0;
    for i in (0..bytes.len()).rev() {
        result = (result << 8) | (bytes[i] as i64);
    }
    if result == 0 {
        return 0;
    }
    if negative { -result } else { result }
}

/// Interpret a script element according to the expected ABI type.
fn interpret_script_element(opcode: u8, data_hex: &str, param_type: &str) -> SdkValue {
    match param_type {
        "int" | "bigint" => {
            if opcode == 0x00 {
                return SdkValue::Int(0);
            }
            if opcode >= 0x51 && opcode <= 0x60 {
                return SdkValue::Int((opcode as i64) - 0x50);
            }
            if opcode == 0x4f {
                return SdkValue::Int(-1);
            }
            SdkValue::Int(decode_script_number(data_hex))
        }
        "bool" => {
            if opcode == 0x00 {
                return SdkValue::Bool(false);
            }
            if opcode == 0x51 {
                return SdkValue::Bool(true);
            }
            SdkValue::Bool(data_hex != "00")
        }
        _ => SdkValue::Bytes(data_hex.to_string()),
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

    // Deduplicate and sort by byteOffset
    let mut seen = std::collections::HashSet::new();
    let mut sorted_slots: Vec<_> = slots.iter().collect();
    sorted_slots.sort_by_key(|s| s.byte_offset);
    sorted_slots.retain(|s| seen.insert(s.param_index));

    let mut result = HashMap::new();
    let mut cumulative_shift: isize = 0;

    for slot in &sorted_slots {
        let adjusted_hex_offset = ((slot.byte_offset as isize) + cumulative_shift) as usize * 2;
        let (data_hex, total_hex_chars, opcode) = read_script_element(&code_hex, adjusted_hex_offset);
        cumulative_shift += (total_hex_chars as isize) / 2 - 1;

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
            abi: Abi {
                constructor: AbiConstructor { params: constructor_params },
                methods: vec![AbiMethod {
                    name: "spend".to_string(),
                    params: vec![],
                    is_public: true,
                    is_terminal: None,
                }],
            },
            script: script.to_string(),
            state_fields: None,
            constructor_slots: Some(slots),
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
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
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
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
    // matches_artifact
    // -----------------------------------------------------------------------

    #[test]
    fn matches_artifact_no_slots() {
        let artifact = RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "5151".to_string(),
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
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
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "5151".to_string(),
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
        };
        // Script with code + OP_RETURN + state data
        assert!(matches_artifact(&artifact, "51516a0000000000000000"));
        // Without state should still match
        assert!(matches_artifact(&artifact, "5151"));
    }
}
