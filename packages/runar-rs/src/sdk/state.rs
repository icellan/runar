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
/// FixedArray state fields are flattened into their synthetic leaves in
/// declaration order and each leaf is encoded with the innermost element
/// type.
pub fn serialize_state(
    fields: &[StateField],
    values: &HashMap<String, SdkValue>,
) -> String {
    let mut sorted: Vec<&StateField> = fields.iter().collect();
    sorted.sort_by_key(|f| f.index);

    let mut hex = String::new();
    for field in sorted {
        if let Some(value) = values.get(&field.name) {
            if let Some(fa) = &field.fixed_array {
                // Flatten the (possibly nested) SdkValue::Array to a flat
                // list of leaves in declaration order.
                let dims = parse_fixed_array_dims(&field.field_type);
                let leaf_type = innermost_element_type(&field.field_type, &fa.element_type);
                let flat = flatten_nested(value, &dims);
                // Each leaf is encoded with the innermost element type.
                for (i, leaf) in flat.iter().enumerate() {
                    let label = fa
                        .synthetic_names
                        .get(i)
                        .map(String::as_str)
                        .unwrap_or(&field.name);
                    hex.push_str(&encode_state_value(leaf, &leaf_type, label));
                }
                continue;
            }
            hex.push_str(&encode_state_value(value, &field.field_type, &field.name));
        }
    }
    hex
}

/// Deserialize state values from a hex-encoded raw byte section.
///
/// The caller must strip the code prefix and OP_RETURN byte before passing
/// the data section. FixedArray state fields are rebuilt into a
/// (possibly nested) `SdkValue::Array` matching the declared shape.
pub fn deserialize_state(
    fields: &[StateField],
    script_hex: &str,
) -> HashMap<String, SdkValue> {
    let mut sorted: Vec<&StateField> = fields.iter().collect();
    sorted.sort_by_key(|f| f.index);

    let mut result = HashMap::new();
    let mut offset = 0;

    for field in sorted {
        if let Some(fa) = &field.fixed_array {
            let dims = parse_fixed_array_dims(&field.field_type);
            let leaf_type = innermost_element_type(&field.field_type, &fa.element_type);
            let mut flat: Vec<SdkValue> = Vec::with_capacity(fa.synthetic_names.len());
            for _ in 0..fa.synthetic_names.len() {
                let (value, bytes_read) = decode_state_value(script_hex, offset, &leaf_type);
                flat.push(value);
                offset += bytes_read;
            }
            let rebuilt = regroup_nested(&flat, &dims);
            result.insert(field.name.clone(), rebuilt);
            continue;
        }
        let (value, bytes_read) = decode_state_value(script_hex, offset, &field.field_type);
        result.insert(field.name.clone(), value);
        offset += bytes_read;
    }

    result
}

/// Parse a type string like `FixedArray<FixedArray<bigint, 3>, 2>` into the
/// outer-first dimensions `[2, 3]`. Returns an empty vec for non-array
/// types.
fn parse_fixed_array_dims(type_str: &str) -> Vec<usize> {
    let mut dims: Vec<usize> = Vec::new();
    let mut cur = type_str;
    while let Some(start) = cur.find("FixedArray<") {
        let inner = &cur[start + "FixedArray<".len()..];
        // Find the matching `>` at depth 0, collecting the inner element
        // and the length after the last `,`.
        let mut depth = 1i32;
        let bytes = inner.as_bytes();
        let mut i = 0usize;
        let mut last_comma = None;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b',' if depth == 1 => last_comma = Some(i),
                _ => {}
            }
            i += 1;
        }
        let end_angle = i;
        if let Some(comma) = last_comma {
            let length_str = inner[comma + 1..end_angle].trim();
            if let Ok(n) = length_str.parse::<usize>() {
                dims.push(n);
            } else {
                return dims;
            }
            cur = &inner[..comma];
        } else {
            return dims;
        }
    }
    dims
}

/// Return the innermost element type string of a (possibly nested)
/// FixedArray type. For `FixedArray<FixedArray<bigint, 2>, 3>` returns
/// `"bigint"`.
fn innermost_element_type(field_type: &str, outer_element_type: &str) -> String {
    // Peel FixedArray<...> layers off outer_element_type until we find a
    // non-FixedArray leaf.
    let mut s = outer_element_type.to_string();
    while s.starts_with("FixedArray<") {
        // extract the inner element part: find "FixedArray<" + "...," at
        // outermost depth, the element is the substring before the last
        // top-level comma.
        let inner = &s["FixedArray<".len()..];
        let bytes = inner.as_bytes();
        let mut depth = 1i32;
        let mut i = 0usize;
        let mut last_comma = None;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b',' if depth == 1 => last_comma = Some(i),
                _ => {}
            }
            i += 1;
        }
        if let Some(comma) = last_comma {
            s = inner[..comma].trim().to_string();
        } else {
            break;
        }
    }
    if s.is_empty() {
        field_type.to_string()
    } else {
        s
    }
}

/// Recursively flatten a nested `SdkValue::Array` (depth = `dims.len()`)
/// into a flat list of leaf `SdkValue`s in declaration order. Missing /
/// wrong-shape values produce `Int(0)` placeholders so the caller can
/// still reach every leaf.
fn flatten_nested(value: &SdkValue, dims: &[usize]) -> Vec<SdkValue> {
    if dims.is_empty() {
        return vec![value.clone()];
    }
    let rest = &dims[1..];
    match value {
        SdkValue::Array(items) => {
            let mut out: Vec<SdkValue> = Vec::new();
            for v in items {
                out.extend(flatten_nested(v, rest));
            }
            out
        }
        _ => {
            let total: usize = dims.iter().product();
            vec![SdkValue::Int(0); total]
        }
    }
}

/// Flatten a state record whose grouped FixedArray entries hold
/// `SdkValue::Array` values into a new record where each leaf is keyed
/// by its underlying synthetic scalar name (`board__0..board__8`,
/// `grid__0__0..grid__1__1`, etc.). Non-array entries are passed
/// through unchanged. The grouped entries are also preserved so callers
/// can still read them.
///
/// Used at the ANF-interpreter boundary, which only knows the expanded
/// scalar property names.
pub fn flatten_fixed_array_state(
    state: &HashMap<String, SdkValue>,
    state_fields: &[StateField],
) -> HashMap<String, SdkValue> {
    let mut out = state.clone();
    for field in state_fields {
        let fa = match &field.fixed_array {
            Some(fa) => fa,
            None => continue,
        };
        let value = match state.get(&field.name) {
            Some(v) => v,
            None => continue,
        };
        let dims = parse_fixed_array_dims(&field.field_type);
        let flat = flatten_nested(value, &dims);
        for (i, synth) in fa.synthetic_names.iter().enumerate() {
            if !out.contains_key(synth) {
                if let Some(leaf) = flat.get(i) {
                    out.insert(synth.clone(), leaf.clone());
                }
            }
        }
    }
    out
}

/// Regroup a state record's synthetic scalar entries back into
/// (possibly nested) `SdkValue::Array` values under their grouped
/// names. Non-synthetic scalars pass through.
pub fn regroup_fixed_array_state(
    state: &HashMap<String, SdkValue>,
    state_fields: &[StateField],
) -> HashMap<String, SdkValue> {
    let mut out = state.clone();
    for field in state_fields {
        let fa = match &field.fixed_array {
            Some(fa) => fa,
            None => continue,
        };
        let mut flat: Vec<Option<SdkValue>> =
            vec![None; fa.synthetic_names.len()];
        let mut saw_any = false;
        for (i, synth) in fa.synthetic_names.iter().enumerate() {
            if let Some(v) = out.get(synth).cloned() {
                flat[i] = Some(v);
                saw_any = true;
            }
        }
        if !saw_any {
            continue;
        }
        // Fill still-missing leaves from a prior grouped value by
        // re-flattening it alongside the scalar updates.
        let dims = parse_fixed_array_dims(&field.field_type);
        if let Some(prior) = state.get(&field.name) {
            let prior_flat = flatten_nested(prior, &dims);
            for (i, slot) in flat.iter_mut().enumerate() {
                if slot.is_none() {
                    if let Some(v) = prior_flat.get(i) {
                        *slot = Some(v.clone());
                    }
                }
            }
        }
        let leaves: Vec<SdkValue> = flat
            .into_iter()
            .map(|o| o.unwrap_or(SdkValue::Int(0)))
            .collect();
        let rebuilt = regroup_nested(&leaves, &dims);
        out.insert(field.name.clone(), rebuilt);
    }
    out
}

/// Recursively rebuild a nested `SdkValue::Array` of depth `dims.len()`
/// from a flat list of leaf values in declaration order.
fn regroup_nested(flat: &[SdkValue], dims: &[usize]) -> SdkValue {
    fn go(flat: &[SdkValue], dims: &[usize], offset: usize) -> (SdkValue, usize) {
        if dims.is_empty() {
            return (flat[offset].clone(), 1);
        }
        let outer = dims[0];
        let rest = &dims[1..];
        let mut items: Vec<SdkValue> = Vec::with_capacity(outer);
        let mut consumed = 0usize;
        for _ in 0..outer {
            let (v, c) = go(flat, rest, offset + consumed);
            items.push(v);
            consumed += c;
        }
        (SdkValue::Array(items), consumed)
    }
    let (v, _) = go(flat, dims, 0);
    v
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
fn encode_state_value(value: &SdkValue, field_type: &str, label: &str) -> String {
    match field_type {
        "int" | "bigint" => {
            // Defensively handle SdkValue::Bytes containing a BigInt string
            // (e.g. "0n", "1000n") that may have slipped through from JSON
            // artifacts loaded without a BigInt reviver.
            let n = state_field_i64(value, label, 8);
            encode_num2bin(n, 8)
        }
        "bool" => {
            if value.as_bool() {
                "01".to_string()
            } else {
                "00".to_string()
            }
        }
        "PubKey" | "Addr" | "Ripemd160" | "Sha256" | "Point" => {
            // Fixed-size byte types: raw hex, no framing needed.
            value.as_bytes().to_string()
        }
        _ => {
            // Variable-length types (ByteString, etc.): use push-data
            // encoding so the decoder can determine the length.
            let hex = value.as_bytes();
            if hex.is_empty() {
                "00".to_string() // OP_0
            } else {
                encode_push_data_state(hex)
            }
        }
    }
}

/// Coerce a bigint state value to `i64` for OP_NUM2BIN encoding, PANICKING if
/// its magnitude does not fit the fixed `width`-byte sign-magnitude state word.
///
/// The check has to run HERE, not inside `encode_num2bin`: the old
/// `bi.to_string().parse::<i64>().unwrap_or(0)` narrowing destroyed an
/// oversized value before any encoder could see it, writing a plausible ZERO
/// with no signal at all.
///
/// `width` bytes of sign-magnitude hold `8*width - 1` magnitude bits — the top
/// bit of the last byte is the sign. `encode_num2bin` writes the low `width`
/// bytes, drops everything above, then ORs the sign bit in on top of whatever
/// landed there, so an oversized value serialises to a plausible but WRONG
/// word:
///
/// ```text
/// 2^63      -> 0000000000000080   reads back as 0   (negative zero)
/// 2^63 + 5  -> 0500000000000080   reads back as -5  (sign flip)
/// 2^64      -> 0000000000000000   reads back as 0
/// ```
///
/// The deploy then succeeded and the UTXO was unspendable: the covenant
/// rebuilds the continuation with the compiler's own OP_NUM2BIN `width`, which
/// cannot produce those bytes from that number, so `hash256(outputs)` never
/// matches. `±(2^(8*width-1) - 1)` stays representable and is unaffected.
///
/// Panics rather than returning a `Result` so `serialize_state` keeps its
/// signature; this is the same "the value cannot be represented, so every
/// result would be wrong" contract as `SdkValue::as_int` and the `i64 overflow`
/// panics in `prelude.rs`.
fn state_field_i64(value: &SdkValue, label: &str, width: usize) -> i64 {
    use num_bigint::BigInt;

    // Resolve the value at ARBITRARY precision first — narrowing is what used
    // to destroy it.
    let wide: Option<BigInt> = match value {
        SdkValue::Int(i) => Some(BigInt::from(*i)),
        SdkValue::BigInt(bi) => Some(bi.clone()),
        // Defensively handle SdkValue::Bytes containing a BigInt string
        // (e.g. "0n", "1000n") that may have slipped through from JSON
        // artifacts loaded without a BigInt reviver.
        SdkValue::Bytes(s) => {
            let num_str = if s.ends_with('n') { &s[..s.len() - 1] } else { s.as_str() };
            num_str.parse::<BigInt>().ok()
        }
        _ => Some(BigInt::from(value.as_int())),
    };

    // A non-numeric byte string keeps the historical lenient behaviour (0).
    let n = match wide {
        Some(n) => n,
        None => return 0,
    };

    let limit = BigInt::from(1) << (8 * width - 1);
    let neg_limit = -limit.clone();
    if n >= limit || n <= neg_limit {
        panic!(
            "serialize_state: bigint state field \"{}\" = {} does not fit the fixed {}-byte \
             sign-magnitude state word (magnitude must be < 2^{}). Serializing it would write a \
             different number into the state section than the contract's on-chain OP_NUM2BIN {} \
             rebuilds, leaving the output unspendable",
            label,
            n,
            width,
            8 * width - 1,
            width
        );
    }

    n.to_string()
        .parse::<i64>()
        .expect("state_field_i64: range-checked value must fit i64")
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

/// Frame a hex-encoded byte string as a state-section field: `<len><data>`.
///
/// This is deliberately NOT the MINIMALDATA push encoding used by
/// `encode_push_data`. The state section is raw data after `OP_RETURN` in the
/// locking script; the interpreter never executes it, so
/// `SCRIPT_VERIFY_MINIMALDATA` — a rule applied to push opcodes as they are
/// executed — does not reach it. What does read it is the compiler's on-chain
/// state codec (`emitPushDataEncode` in
/// packages/runar-compiler/src/passes/05-stack-lower.ts), which writes and
/// parses `<len><data>`. Both sides must agree byte for byte or the
/// continuation hash check fails and the contract is unspendable.
///
/// #110 applied the MINIMALDATA short-circuit here, in all seven SDKs and none
/// of the seven compilers, so a 1-byte `0x05` state field serialised off-chain
/// as `55` while the script rebuilt it as `0105`. Byte-identical with the
/// other six SDKs.
pub(crate) fn encode_push_data_state(data_hex: &str) -> String {
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

/// Wrap a hex-encoded byte string in a Bitcoin Script push data opcode, for
/// pushes the interpreter will EXECUTE (unlocking scripts, spliced ctor args).
///
/// Applies BSV consensus rule `SCRIPT_VERIFY_MINIMALDATA` for single-byte
/// pushes: a 1-byte payload whose value is in `{0x01..=0x10, 0x81}` MUST use
/// the corresponding minimal opcode (`OP_1..OP_16` / `OP_1NEGATE`) rather
/// than the direct push `01 NN`. Non-minimal direct pushes are rejected by
/// ARC, TAAL ARC, and WhatsOnChain at the relay layer with the error:
///   `non-mandatory-script-verify-flag (Data push larger than necessary)`
///
/// NOTE: 0x00 is deliberately NOT in that set. `OP_0` pushes the EMPTY byte
/// array, not a 1-byte `0x00` — so the minimal encoding of a 1-byte `0x00`
/// payload is the direct push `01 00` (matching the compiler's
/// `encodePushBytesHex` in push-encoding.ts), not `OP_0` (C9 / S1).
pub fn encode_push_data(data_hex: &str) -> String {
    let len = data_hex.len() / 2;

    // MINIMALDATA: single-byte payloads in the OP_N range must use the
    // corresponding minimal opcode. Mirrors the same rule already enforced
    // by `encode_script_number` for `SdkValue::Int` (which short-circuits
    // to `OP_N` opcodes for n in 1..=16). The encoder for `SdkValue::Bytes`
    // did not previously honor this rule, so an arbitrary ByteString that
    // happened to be a single byte in this range produced a relay-rejected
    // direct push.
    if len == 1 {
        if let Ok(byte) = u8::from_str_radix(data_hex, 16) {
            match byte {
                0x01..=0x10 => return format!("{:02x}", 0x50 + byte),  // OP_1..OP_16
                0x81 => return "4f".to_string(),                       // OP_1NEGATE
                _ => {}
            }
        }
    }

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

/// Decode a state-section field at the given hex offset.
/// Returns the field data (hex) and the total number of hex chars consumed.
///
/// Exact inverse of `encode_push_data_state`, and deliberately as strict as
/// the compiler's on-chain state reader: only `<len><data>` framing is
/// understood. `OP_1..OP_16` (0x51..=0x60) and `OP_1NEGATE` (0x4f) are NOT
/// decoded as single-byte values — accepting them would let the SDK read a
/// state section the contract's own script cannot parse. `OP_0` (0x00) falls
/// through to the `opcode <= 75` branch below and correctly decodes as the
/// empty byte array (0-length push).
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
                fixed_array: None,
            })
            .collect()
    }

    fn make_fa_field(
        name: &str,
        field_type: &str,
        length: usize,
        element_type: &str,
        synthetic_names: Vec<&str>,
        index: usize,
    ) -> StateField {
        StateField {
            name: name.to_string(),
            field_type: field_type.to_string(),
            index,
            initial_value: None,
            fixed_array: Some(super::super::types::FixedArrayInfo {
                element_type: element_type.to_string(),
                length,
                synthetic_names: synthetic_names.into_iter().map(String::from).collect(),
            }),
        }
    }

    fn make_values(pairs: &[(&str, SdkValue)]) -> HashMap<String, SdkValue> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    // -----------------------------------------------------------------------
    // FixedArray roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrips_flat_fixed_array_state() {
        let fields = vec![make_fa_field(
            "board",
            "FixedArray<bigint, 3>",
            3,
            "bigint",
            vec!["board__0", "board__1", "board__2"],
            0,
        )];
        let values = make_values(&[(
            "board",
            SdkValue::Array(vec![
                SdkValue::Int(7),
                SdkValue::Int(11),
                SdkValue::Int(13),
            ]),
        )]);
        let hex = serialize_state(&fields, &values);
        let round = deserialize_state(&fields, &hex);
        assert_eq!(
            round["board"],
            SdkValue::Array(vec![
                SdkValue::Int(7),
                SdkValue::Int(11),
                SdkValue::Int(13),
            ])
        );
    }

    #[test]
    fn roundtrips_nested_fixed_array_state() {
        let fields = vec![make_fa_field(
            "grid",
            "FixedArray<FixedArray<bigint, 2>, 2>",
            2,
            "FixedArray<bigint, 2>",
            vec!["grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1"],
            0,
        )];
        let values = make_values(&[(
            "grid",
            SdkValue::Array(vec![
                SdkValue::Array(vec![SdkValue::Int(1), SdkValue::Int(2)]),
                SdkValue::Array(vec![SdkValue::Int(3), SdkValue::Int(4)]),
            ]),
        )]);
        let hex = serialize_state(&fields, &values);
        let round = deserialize_state(&fields, &hex);
        assert_eq!(
            round["grid"],
            SdkValue::Array(vec![
                SdkValue::Array(vec![SdkValue::Int(1), SdkValue::Int(2)]),
                SdkValue::Array(vec![SdkValue::Int(3), SdkValue::Int(4)]),
            ])
        );
    }

    #[test]
    fn flatten_and_regroup_state_round_trip() {
        let fields = vec![make_fa_field(
            "board",
            "FixedArray<bigint, 3>",
            3,
            "bigint",
            vec!["board__0", "board__1", "board__2"],
            0,
        )];
        let state: HashMap<String, SdkValue> = make_values(&[(
            "board",
            SdkValue::Array(vec![
                SdkValue::Int(10),
                SdkValue::Int(20),
                SdkValue::Int(30),
            ]),
        )]);
        let flat = flatten_fixed_array_state(&state, &fields);
        assert_eq!(flat.get("board__0"), Some(&SdkValue::Int(10)));
        assert_eq!(flat.get("board__1"), Some(&SdkValue::Int(20)));
        assert_eq!(flat.get("board__2"), Some(&SdkValue::Int(30)));
        // Regroup drops the flat leaves back into an array.
        let mut flat_only: HashMap<String, SdkValue> = HashMap::new();
        flat_only.insert("board__0".to_string(), SdkValue::Int(100));
        flat_only.insert("board__1".to_string(), SdkValue::Int(200));
        flat_only.insert("board__2".to_string(), SdkValue::Int(300));
        let grouped = regroup_fixed_array_state(&flat_only, &fields);
        assert_eq!(
            grouped["board"],
            SdkValue::Array(vec![
                SdkValue::Int(100),
                SdkValue::Int(200),
                SdkValue::Int(300),
            ])
        );
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
            parent_class: None,
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "76a988ac".to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
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
            parent_class: None,
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: Some(vec![]),
            constructor_slots: None,
            code_sep_index_slots: None,
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
            parent_class: None,
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: Some(fields),
            constructor_slots: None,
            code_sep_index_slots: None,
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
            parent_class: None,
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: Some(fields),
            constructor_slots: None,
            code_sep_index_slots: None,
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
            parent_class: None,
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: Some(fields),
            constructor_slots: None,
            code_sep_index_slots: None,
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
            parent_class: None,
            abi: super::super::types::Abi {
                constructor: super::super::types::AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "ac".to_string(),
            asm: None,
            state_fields: Some(fields),
            constructor_slots: None,
            code_sep_index_slots: None,
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

/// A bigint state value whose MAGNITUDE does not fit the fixed 8-byte
/// little-endian sign-magnitude word must be REFUSED, not silently truncated.
///
/// `num2bin-le8` gives a bigint state field exactly 63 bits of magnitude
/// (bytes 0..6 plus the low 7 bits of byte 7) and one sign bit (0x80 of byte
/// 7). Measured in the TS reference before the guard:
///
/// ```text
/// value       bytes written       reads back as
/// 2^63        0000000000000080    0    (negative zero)
/// 2^63 + 5    0500000000000080    -5   (SIGN FLIP)
/// 2^64        0000000000000000    0
/// ```
///
/// The Rust tier corrupted EARLIER and even more quietly: `encode_state_value`
/// narrowed the value with `.parse::<i64>().unwrap_or(0)`, so an oversized
/// `SdkValue::BigInt` wrote a plausible ZERO with no signal at all. The guard
/// therefore lives where the wide value still exists, not in `encode_num2bin`.
///
/// Expected bytes below are derived BY HAND from the sign-magnitude rule,
/// never read off the serializer.
#[cfg(test)]
mod state_range_guard_tests {
    use super::*;
    use num_bigint::BigInt;

    fn count_field() -> Vec<StateField> {
        vec![StateField {
            name: "count".to_string(),
            field_type: "bigint".to_string(),
            index: 0,
            initial_value: None,
            fixed_array: None,
        }]
    }

    fn one_value(v: SdkValue) -> HashMap<String, SdkValue> {
        let mut m = HashMap::new();
        m.insert("count".to_string(), v);
        m
    }

    fn big(decimal: &str) -> SdkValue {
        SdkValue::BigInt(decimal.parse::<BigInt>().unwrap())
    }

    fn encode(v: SdkValue) -> String {
        serialize_state(&count_field(), &one_value(v))
    }

    // -----------------------------------------------------------------
    // Rejecting
    // -----------------------------------------------------------------

    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_two_pow_63() {
        encode(big("9223372036854775808"));
    }

    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_negative_two_pow_63_bigint() {
        encode(big("-9223372036854775808"));
    }

    /// -2^63 IS a valid i64, but its MAGNITUDE is 2^63 — one past the 63
    /// magnitude bits — and it encoded as negative zero (0000000000000080).
    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_i64_min() {
        encode(SdkValue::Int(i64::MIN));
    }

    /// The sign-flip case: used to write 0500000000000080, which reads back
    /// as -5 — a positive balance deserialising as a debt.
    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_two_pow_63_plus_5() {
        encode(big("9223372036854775813"));
    }

    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_two_pow_64() {
        encode(big("18446744073709551616"));
    }

    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_two_pow_70() {
        encode(big("1180591620717411303424"));
    }

    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_negative_two_pow_70() {
        encode(big("-1180591620717411303424"));
    }

    /// The unrevived-JSON path: `SdkValue::Bytes("...n")` used to
    /// `.parse::<i64>().unwrap_or(0)` and write a silent zero.
    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_out_of_range_bigint_string() {
        encode(SdkValue::Bytes("9223372036854775808n".to_string()));
    }

    #[test]
    fn names_the_field_and_the_value_it_refused() {
        let err = std::panic::catch_unwind(|| encode(big("9223372036854775808"))).unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()).unwrap());
        assert!(msg.contains("count"), "message must name the field: {}", msg);
        assert!(
            msg.contains("9223372036854775808"),
            "message must quote the value: {}",
            msg
        );
    }

    #[test]
    #[should_panic(expected = "does not fit")]
    fn rejects_out_of_range_fixed_array_element() {
        let fields = vec![StateField {
            name: "slots".to_string(),
            field_type: "FixedArray<bigint, 2>".to_string(),
            index: 0,
            initial_value: None,
            fixed_array: Some(crate::sdk::types::FixedArrayInfo {
                element_type: "bigint".to_string(),
                length: 2,
                synthetic_names: vec!["slots__0".to_string(), "slots__1".to_string()],
            }),
        }];
        let mut values = HashMap::new();
        values.insert(
            "slots".to_string(),
            SdkValue::Array(vec![SdkValue::Int(1), big("9223372036854775808")]),
        );
        serialize_state(&fields, &values);
    }

    // -----------------------------------------------------------------
    // Accepting controls — byte-exact, and they must stay byte-exact
    // -----------------------------------------------------------------

    #[test]
    fn accepts_max_magnitude_byte_exact() {
        // magnitude bytes 0..6 all 0xff, byte 7 = 0x7f (seven magnitude bits
        // set, sign bit clear).
        assert_eq!(encode(SdkValue::Int(i64::MAX)), "ffffffffffffff7f");
        assert_eq!(encode(big("9223372036854775807")), "ffffffffffffff7f");
        assert_eq!(
            encode(SdkValue::Bytes("9223372036854775807n".to_string())),
            "ffffffffffffff7f"
        );
        // same magnitude, sign bit set: 0x7f | 0x80 = 0xff.
        assert_eq!(encode(SdkValue::Int(-i64::MAX)), "ffffffffffffffff");
        assert_eq!(encode(big("-9223372036854775807")), "ffffffffffffffff");
        assert_eq!(
            encode(SdkValue::Bytes("-9223372036854775807n".to_string())),
            "ffffffffffffffff"
        );
    }

    #[test]
    fn accepts_the_small_values_every_shipped_contract_uses() {
        assert_eq!(encode(SdkValue::Int(0)), "0000000000000000");
        assert_eq!(encode(SdkValue::Int(1)), "0100000000000000");
        assert_eq!(encode(SdkValue::Int(-1)), "0100000000000080");
        assert_eq!(encode(SdkValue::Int(127)), "7f00000000000000");
        assert_eq!(encode(SdkValue::Int(-127)), "7f00000000000080");
        assert_eq!(encode(SdkValue::Int(128)), "8000000000000000");
        assert_eq!(encode(SdkValue::Int(-128)), "8000000000000080");
    }
}
