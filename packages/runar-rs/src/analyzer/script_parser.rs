//! Pass 1: hex → opcode list. See spec §4 (naming) and §6 (push encoding).
//!
//! Truncated pushes are emitted with whatever data is available; no
//! dedicated finding is produced (spec §6.1).

use super::types::{ParsedOp, PushEncoding, RawScriptSpan};

/// Normalize a hex string: strip whitespace, lowercase.
pub fn normalize_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_whitespace() {
            continue;
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Decode a normalized lowercase hex string into bytes. Returns `None` on
/// odd length or invalid hex characters.
pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Canonical opcode name per spec §4.1. Returns `OP_UNKNOWN(0xNN)` for
/// bytes not in the BSV table.
pub fn opcode_name(byte: u8) -> String {
    match byte {
        0x00 => "OP_0".to_string(),
        0x4c => "OP_PUSHDATA1".to_string(),
        0x4d => "OP_PUSHDATA2".to_string(),
        0x4e => "OP_PUSHDATA4".to_string(),
        0x4f => "OP_1NEGATE".to_string(),
        0x51 => "OP_1".to_string(),
        0x52 => "OP_2".to_string(),
        0x53 => "OP_3".to_string(),
        0x54 => "OP_4".to_string(),
        0x55 => "OP_5".to_string(),
        0x56 => "OP_6".to_string(),
        0x57 => "OP_7".to_string(),
        0x58 => "OP_8".to_string(),
        0x59 => "OP_9".to_string(),
        0x5a => "OP_10".to_string(),
        0x5b => "OP_11".to_string(),
        0x5c => "OP_12".to_string(),
        0x5d => "OP_13".to_string(),
        0x5e => "OP_14".to_string(),
        0x5f => "OP_15".to_string(),
        0x60 => "OP_16".to_string(),
        0x61 => "OP_NOP".to_string(),
        0x63 => "OP_IF".to_string(),
        0x64 => "OP_NOTIF".to_string(),
        0x67 => "OP_ELSE".to_string(),
        0x68 => "OP_ENDIF".to_string(),
        0x69 => "OP_VERIFY".to_string(),
        0x6a => "OP_RETURN".to_string(),
        0x6b => "OP_TOALTSTACK".to_string(),
        0x6c => "OP_FROMALTSTACK".to_string(),
        0x6d => "OP_2DROP".to_string(),
        0x6e => "OP_2DUP".to_string(),
        0x6f => "OP_3DUP".to_string(),
        0x70 => "OP_2OVER".to_string(),
        0x71 => "OP_2ROT".to_string(),
        0x72 => "OP_2SWAP".to_string(),
        0x73 => "OP_IFDUP".to_string(),
        0x74 => "OP_DEPTH".to_string(),
        0x75 => "OP_DROP".to_string(),
        0x76 => "OP_DUP".to_string(),
        0x77 => "OP_NIP".to_string(),
        0x78 => "OP_OVER".to_string(),
        0x79 => "OP_PICK".to_string(),
        0x7a => "OP_ROLL".to_string(),
        0x7b => "OP_ROT".to_string(),
        0x7c => "OP_SWAP".to_string(),
        0x7d => "OP_TUCK".to_string(),
        0x7e => "OP_CAT".to_string(),
        0x7f => "OP_SPLIT".to_string(),
        0x80 => "OP_NUM2BIN".to_string(),
        0x81 => "OP_BIN2NUM".to_string(),
        0x82 => "OP_SIZE".to_string(),
        0x83 => "OP_INVERT".to_string(),
        0x84 => "OP_AND".to_string(),
        0x85 => "OP_OR".to_string(),
        0x86 => "OP_XOR".to_string(),
        0x87 => "OP_EQUAL".to_string(),
        0x88 => "OP_EQUALVERIFY".to_string(),
        0x8b => "OP_1ADD".to_string(),
        0x8c => "OP_1SUB".to_string(),
        0x8f => "OP_NEGATE".to_string(),
        0x90 => "OP_ABS".to_string(),
        0x91 => "OP_NOT".to_string(),
        0x92 => "OP_0NOTEQUAL".to_string(),
        0x93 => "OP_ADD".to_string(),
        0x94 => "OP_SUB".to_string(),
        0x95 => "OP_MUL".to_string(),
        0x96 => "OP_DIV".to_string(),
        0x97 => "OP_MOD".to_string(),
        0x98 => "OP_LSHIFT".to_string(),
        0x99 => "OP_RSHIFT".to_string(),
        0x9a => "OP_BOOLAND".to_string(),
        0x9b => "OP_BOOLOR".to_string(),
        0x9c => "OP_NUMEQUAL".to_string(),
        0x9d => "OP_NUMEQUALVERIFY".to_string(),
        0x9e => "OP_NUMNOTEQUAL".to_string(),
        0x9f => "OP_LESSTHAN".to_string(),
        0xa0 => "OP_GREATERTHAN".to_string(),
        0xa1 => "OP_LESSTHANOREQUAL".to_string(),
        0xa2 => "OP_GREATERTHANOREQUAL".to_string(),
        0xa3 => "OP_MIN".to_string(),
        0xa4 => "OP_MAX".to_string(),
        0xa5 => "OP_WITHIN".to_string(),
        0xa6 => "OP_RIPEMD160".to_string(),
        0xa7 => "OP_SHA1".to_string(),
        0xa8 => "OP_SHA256".to_string(),
        0xa9 => "OP_HASH160".to_string(),
        0xaa => "OP_HASH256".to_string(),
        0xab => "OP_CODESEPARATOR".to_string(),
        0xac => "OP_CHECKSIG".to_string(),
        0xad => "OP_CHECKSIGVERIFY".to_string(),
        0xae => "OP_CHECKMULTISIG".to_string(),
        0xaf => "OP_CHECKMULTISIGVERIFY".to_string(),
        b => format!("OP_UNKNOWN(0x{:02x})", b),
    }
}

/// Parse a normalized hex script into the opcode list. Returns the parsed
/// operations. Truncation is silent.
pub fn parse_script(hex: &str) -> Vec<ParsedOp> {
    let bytes = decode_hex(hex).unwrap_or_default();
    parse_bytes(&bytes)
}

fn parse_bytes(bytes: &[u8]) -> Vec<ParsedOp> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        let offset = i;
        if (0x01..=0x4b).contains(&op) {
            // Direct push
            let len = op as usize;
            let data_start = i + 1;
            let data_end = (data_start + len).min(bytes.len());
            let data = bytes[data_start..data_end].to_vec();
            let actual_len = data.len();
            out.push(ParsedOp {
                offset,
                opcode: op as i16,
                name: format!("PUSH_{}", actual_len),
                size: 1 + actual_len,
                data: Some(data),
                push_encoding: Some(PushEncoding::Direct),
                declared_data_length: Some(len),
                raw_span_arity: None,
            });
            i = data_end;
            // If truncated (data_end < data_start+len), stop parsing.
            if actual_len < len {
                break;
            }
        } else if op == 0x4c {
            // PUSHDATA1
            if i + 1 >= bytes.len() {
                out.push(ParsedOp {
                    offset,
                    opcode: op as i16,
                    name: "OP_PUSHDATA1".to_string(),
                    size: bytes.len() - i,
                    data: Some(Vec::new()),
                    push_encoding: Some(PushEncoding::Pushdata1),
                    declared_data_length: Some(0),
                    raw_span_arity: None,
                });
                break;
            }
            let len = bytes[i + 1] as usize;
            let data_start = i + 2;
            let data_end = (data_start + len).min(bytes.len());
            let data = bytes[data_start..data_end].to_vec();
            let actual_len = data.len();
            out.push(ParsedOp {
                offset,
                opcode: op as i16,
                name: "OP_PUSHDATA1".to_string(),
                size: 2 + actual_len,
                data: Some(data),
                push_encoding: Some(PushEncoding::Pushdata1),
                declared_data_length: Some(len),
                raw_span_arity: None,
            });
            i = data_end;
            if actual_len < len {
                break;
            }
        } else if op == 0x4d {
            // PUSHDATA2
            if i + 2 >= bytes.len() {
                out.push(ParsedOp {
                    offset,
                    opcode: op as i16,
                    name: "OP_PUSHDATA2".to_string(),
                    size: bytes.len() - i,
                    data: Some(Vec::new()),
                    push_encoding: Some(PushEncoding::Pushdata2),
                    declared_data_length: Some(0),
                    raw_span_arity: None,
                });
                break;
            }
            let len = (bytes[i + 1] as usize) | ((bytes[i + 2] as usize) << 8);
            let data_start = i + 3;
            let data_end = (data_start + len).min(bytes.len());
            let data = bytes[data_start..data_end].to_vec();
            let actual_len = data.len();
            out.push(ParsedOp {
                offset,
                opcode: op as i16,
                name: "OP_PUSHDATA2".to_string(),
                size: 3 + actual_len,
                data: Some(data),
                push_encoding: Some(PushEncoding::Pushdata2),
                declared_data_length: Some(len),
                raw_span_arity: None,
            });
            i = data_end;
            if actual_len < len {
                break;
            }
        } else if op == 0x4e {
            // PUSHDATA4
            if i + 4 >= bytes.len() {
                out.push(ParsedOp {
                    offset,
                    opcode: op as i16,
                    name: "OP_PUSHDATA4".to_string(),
                    size: bytes.len() - i,
                    data: Some(Vec::new()),
                    push_encoding: Some(PushEncoding::Pushdata4),
                    declared_data_length: Some(0),
                    raw_span_arity: None,
                });
                break;
            }
            let len = (bytes[i + 1] as usize)
                | ((bytes[i + 2] as usize) << 8)
                | ((bytes[i + 3] as usize) << 16)
                | ((bytes[i + 4] as usize) << 24);
            let data_start = i + 5;
            let data_end = (data_start + len).min(bytes.len());
            let data = bytes[data_start..data_end].to_vec();
            let actual_len = data.len();
            out.push(ParsedOp {
                offset,
                opcode: op as i16,
                name: "OP_PUSHDATA4".to_string(),
                size: 5 + actual_len,
                data: Some(data),
                push_encoding: Some(PushEncoding::Pushdata4),
                declared_data_length: Some(len),
                raw_span_arity: None,
            });
            i = data_end;
            if actual_len < len {
                break;
            }
        } else if op == 0x00 || op == 0x4f || (0x51..=0x60).contains(&op) {
            // OP_0, OP_1NEGATE, OP_1..OP_16
            out.push(ParsedOp {
                offset,
                opcode: op as i16,
                name: opcode_name(op),
                size: 1,
                data: None,
                push_encoding: Some(PushEncoding::OpN),
                declared_data_length: None,
                raw_span_arity: None,
            });
            i += 1;
        } else {
            // Plain opcode (no data)
            out.push(ParsedOp {
                offset,
                opcode: op as i16,
                name: opcode_name(op),
                size: 1,
                data: None,
                push_encoding: None,
                declared_data_length: None,
                raw_span_arity: None,
            });
            i += 1;
        }
    }
    out
}

/// Collapse raw-script spans (spec §12). Spans whose end is before any
/// remaining opcode are skipped. Opcodes entirely within a span are
/// dropped and replaced (once per span) by a synthetic `RAW_SPAN` step.
pub fn collapse_raw_script_spans(
    opcodes: Vec<ParsedOp>,
    spans: &[RawScriptSpan],
) -> Vec<ParsedOp> {
    if spans.is_empty() {
        return opcodes;
    }
    let mut sorted: Vec<RawScriptSpan> = spans.to_vec();
    sorted.sort_by_key(|s| s.offset);

    let mut out: Vec<ParsedOp> = Vec::with_capacity(opcodes.len());
    let mut span_idx = 0usize;

    for op in opcodes.into_iter() {
        // Advance past spans that ended before this opcode begins.
        while span_idx < sorted.len() {
            let span_end = sorted[span_idx].offset + sorted[span_idx].length;
            if span_end <= op.offset {
                span_idx += 1;
            } else {
                break;
            }
        }
        if span_idx >= sorted.len() {
            out.push(op);
            continue;
        }
        let span = &sorted[span_idx];
        let span_end = span.offset + span.length;
        // Opcode entirely before the span.
        if op.offset + op.size <= span.offset {
            out.push(op);
            continue;
        }
        // Opcode entirely inside the span — drop, emit synthetic if not already.
        if op.offset >= span.offset && op.offset + op.size <= span_end {
            let need_synth = match out.last() {
                Some(last) => last.opcode != -1 || last.offset != span.offset,
                None => true,
            };
            if need_synth {
                out.push(ParsedOp {
                    offset: span.offset,
                    opcode: -1,
                    name: "RAW_SPAN".to_string(),
                    size: span.length,
                    data: None,
                    push_encoding: None,
                    declared_data_length: None,
                    raw_span_arity: Some((span.in_arity, span.out_arity)),
                });
            }
            continue;
        }
        // Partial overlap / degenerate — drop opcode, emit synthetic once.
        let need_synth = match out.last() {
            Some(last) => last.opcode != -1 || last.offset != span.offset,
            None => true,
        };
        if need_synth {
            out.push(ParsedOp {
                offset: span.offset,
                opcode: -1,
                name: "RAW_SPAN".to_string(),
                size: span.length,
                data: None,
                push_encoding: None,
                declared_data_length: None,
                raw_span_arity: Some((span.in_arity, span.out_arity)),
            });
        }
    }
    out
}
