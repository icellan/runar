//! 1sat ordinals support: inscription envelope build/parse and BSV-20/BSV-21 helpers.
//!
//! Envelope layout:
//!   OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(<content-type>) OP_0 PUSH(<data>) OP_ENDIF
//!
//! Hex:
//!   00 63 03 6f7264 51 <push content-type> 00 <push data> 68
//!
//! The envelope is a no-op (OP_FALSE causes the IF block to be skipped)
//! and can be placed anywhere in a script without affecting execution.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Inscription data: content type and hex-encoded payload.
///
/// The `data` field is a hex string representing the raw inscription bytes.
/// For text content, encode the UTF-8 bytes as hex first. For BSV-20 JSON,
/// use the `bsv20_*` / `bsv21_*` helper functions which handle encoding.
#[derive(Debug, Clone, PartialEq)]
pub struct Inscription {
    pub content_type: String,
    pub data: String, // hex-encoded content
}

/// Hex-char offsets bounding an inscription envelope within a script.
/// Used internally by `find_inscription_envelope` and `strip_inscription_envelope`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvelopeBounds {
    /// Hex-char offset where the envelope starts (at OP_FALSE).
    pub start_hex: usize,
    /// Hex-char offset where the envelope ends (after OP_ENDIF).
    pub end_hex: usize,
}

// ---------------------------------------------------------------------------
// Push-data encoding (mirrors state.rs encode_push_data)
// ---------------------------------------------------------------------------

fn encode_push_data(data_hex: &str) -> String {
    if data_hex.is_empty() {
        return "00".to_string(); // OP_0
    }
    let len = data_hex.len() / 2;

    if len <= 75 {
        format!("{:02x}{}", len, data_hex)
    } else if len <= 0xff {
        format!("4c{:02x}{}", len, data_hex)
    } else if len <= 0xffff {
        format!("4d{:02x}{:02x}{}", len & 0xff, (len >> 8) & 0xff, data_hex)
    } else {
        format!(
            "4e{:02x}{:02x}{:02x}{:02x}{}",
            len & 0xff,
            (len >> 8) & 0xff,
            (len >> 16) & 0xff,
            (len >> 24) & 0xff,
            data_hex,
        )
    }
}

// ---------------------------------------------------------------------------
// UTF-8 <-> Hex helpers
// ---------------------------------------------------------------------------

fn utf8_to_hex(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_utf8(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= hex.len() {
                u8::from_str_radix(&hex[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build a 1sat ordinals inscription envelope as hex.
///
/// # Arguments
/// * `content_type` - MIME type (e.g. "image/png", "application/bsv-20")
/// * `data` - Hex-encoded inscription content
///
/// # Returns
/// Hex string of the full envelope script fragment.
pub fn build_inscription_envelope(content_type: &str, data: &str) -> String {
    let content_type_hex = utf8_to_hex(content_type);

    // OP_FALSE (00) OP_IF (63) PUSH "ord" (03 6f7264) OP_1 (51)
    let mut hex = String::from("006303");
    hex.push_str("6f7264");
    hex.push_str("51");
    // PUSH content-type
    hex.push_str(&encode_push_data(&content_type_hex));
    // OP_0 (00) -- content delimiter
    hex.push_str("00");
    // PUSH data
    hex.push_str(&encode_push_data(data));
    // OP_ENDIF (68)
    hex.push_str("68");

    hex
}

// ---------------------------------------------------------------------------
// Parse / Find helpers
// ---------------------------------------------------------------------------

/// Read a push-data value at the given hex offset. Returns the pushed data
/// (hex) and the total number of hex chars consumed (including the length
/// prefix).
fn read_push_data(script_hex: &str, offset: usize) -> Option<(String, usize)> {
    if offset + 2 > script_hex.len() {
        return None;
    }
    let opcode = u8::from_str_radix(&script_hex[offset..offset + 2], 16).ok()?;

    if opcode >= 0x01 && opcode <= 0x4b {
        let data_len = opcode as usize * 2;
        if offset + 2 + data_len > script_hex.len() {
            return None;
        }
        Some((script_hex[offset + 2..offset + 2 + data_len].to_string(), 2 + data_len))
    } else if opcode == 0x4c {
        // OP_PUSHDATA1
        if offset + 4 > script_hex.len() {
            return None;
        }
        let len = usize::from(u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).ok()?);
        let data_len = len * 2;
        if offset + 4 + data_len > script_hex.len() {
            return None;
        }
        Some((script_hex[offset + 4..offset + 4 + data_len].to_string(), 4 + data_len))
    } else if opcode == 0x4d {
        // OP_PUSHDATA2
        if offset + 6 > script_hex.len() {
            return None;
        }
        let lo = usize::from(u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).ok()?);
        let hi = usize::from(u8::from_str_radix(&script_hex[offset + 4..offset + 6], 16).ok()?);
        let len = lo | (hi << 8);
        let data_len = len * 2;
        if offset + 6 + data_len > script_hex.len() {
            return None;
        }
        Some((script_hex[offset + 6..offset + 6 + data_len].to_string(), 6 + data_len))
    } else if opcode == 0x4e {
        // OP_PUSHDATA4
        if offset + 10 > script_hex.len() {
            return None;
        }
        let b0 = usize::from(u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).ok()?);
        let b1 = usize::from(u8::from_str_radix(&script_hex[offset + 4..offset + 6], 16).ok()?);
        let b2 = usize::from(u8::from_str_radix(&script_hex[offset + 6..offset + 8], 16).ok()?);
        let b3 = usize::from(u8::from_str_radix(&script_hex[offset + 8..offset + 10], 16).ok()?);
        let len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        let data_len = len * 2;
        if offset + 10 + data_len > script_hex.len() {
            return None;
        }
        Some((script_hex[offset + 10..offset + 10 + data_len].to_string(), 10 + data_len))
    } else {
        None
    }
}

/// Compute the number of hex chars an opcode occupies (including its push
/// data) so we can advance past it while walking a script.
fn opcode_size(script_hex: &str, offset: usize) -> usize {
    if offset + 2 > script_hex.len() {
        return 2;
    }
    let opcode = match u8::from_str_radix(&script_hex[offset..offset + 2], 16) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    if opcode >= 0x01 && opcode <= 0x4b {
        2 + opcode as usize * 2
    } else if opcode == 0x4c {
        if offset + 4 > script_hex.len() {
            return 2;
        }
        let len = u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        4 + len * 2
    } else if opcode == 0x4d {
        if offset + 6 > script_hex.len() {
            return 2;
        }
        let lo = u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let hi = u8::from_str_radix(&script_hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
        6 + (lo | (hi << 8)) * 2
    } else if opcode == 0x4e {
        if offset + 10 > script_hex.len() {
            return 2;
        }
        let b0 = u8::from_str_radix(&script_hex[offset + 2..offset + 4], 16).unwrap_or(0) as usize;
        let b1 = u8::from_str_radix(&script_hex[offset + 4..offset + 6], 16).unwrap_or(0) as usize;
        let b2 = u8::from_str_radix(&script_hex[offset + 6..offset + 8], 16).unwrap_or(0) as usize;
        let b3 = u8::from_str_radix(&script_hex[offset + 8..offset + 10], 16).unwrap_or(0) as usize;
        10 + (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) * 2
    } else {
        2 // all other opcodes are 1 byte
    }
}

// ---------------------------------------------------------------------------
// Find
// ---------------------------------------------------------------------------

/// Find the inscription envelope within a script hex string.
///
/// Walks the script as Bitcoin Script opcodes looking for the pattern:
///   OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) ...
///
/// Returns hex-char offsets of the envelope, or None if not found.
pub fn find_inscription_envelope(script_hex: &str) -> Option<EnvelopeBounds> {
    let mut offset = 0;
    let len = script_hex.len();

    while offset + 2 <= len {
        let opcode = u8::from_str_radix(&script_hex[offset..offset + 2], 16).ok()?;

        // Look for OP_FALSE (0x00)
        if opcode == 0x00 {
            // Check: OP_IF (63) PUSH3 (03) "ord" (6f7264)
            if offset + 12 <= len
                && &script_hex[offset + 2..offset + 4] == "63"    // OP_IF
                && &script_hex[offset + 4..offset + 12] == "036f7264" // PUSH3 "ord"
            {
                let envelope_start = offset;
                // Skip: OP_FALSE(2) + OP_IF(2) + PUSH3 "ord"(8) = 12 hex chars
                let mut pos = offset + 12;

                // Expect OP_1 (0x51)
                if pos + 2 > len || &script_hex[pos..pos + 2] != "51" {
                    offset += 2;
                    continue;
                }
                pos += 2; // skip OP_1

                // Read content-type push
                let ct_push = match read_push_data(script_hex, pos) {
                    Some(p) => p,
                    None => { offset += 2; continue; }
                };
                pos += ct_push.1;

                // Expect OP_0 (0x00) -- content delimiter
                if pos + 2 > len || &script_hex[pos..pos + 2] != "00" {
                    offset += 2;
                    continue;
                }
                pos += 2; // skip OP_0

                // Read data push
                let data_push = match read_push_data(script_hex, pos) {
                    Some(p) => p,
                    None => { offset += 2; continue; }
                };
                pos += data_push.1;

                // Expect OP_ENDIF (0x68)
                if pos + 2 > len || &script_hex[pos..pos + 2] != "68" {
                    offset += 2;
                    continue;
                }
                pos += 2; // skip OP_ENDIF

                return Some(EnvelopeBounds {
                    start_hex: envelope_start,
                    end_hex: pos,
                });
            }
        }

        // Advance past this opcode
        offset += opcode_size(script_hex, offset);
    }

    None
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/// Parse an inscription envelope from a script hex string.
///
/// Returns the inscription data, or None if no envelope is found.
pub fn parse_inscription_envelope(script_hex: &str) -> Option<Inscription> {
    let bounds = find_inscription_envelope(script_hex)?;
    let envelope_hex = &script_hex[bounds.start_hex..bounds.end_hex];

    // Parse the envelope contents:
    // 00 63 03 6f7264 51 <ct-push> 00 <data-push> 68
    let mut pos = 12; // skip OP_FALSE + OP_IF + PUSH3 "ord"
    pos += 2; // skip OP_1

    let (ct_data, ct_read) = read_push_data(envelope_hex, pos)?;
    pos += ct_read;

    pos += 2; // skip OP_0

    let (data, _) = read_push_data(envelope_hex, pos)?;

    Some(Inscription {
        content_type: hex_to_utf8(&ct_data),
        data,
    })
}

// ---------------------------------------------------------------------------
// Strip
// ---------------------------------------------------------------------------

/// Remove the inscription envelope from a script, returning the bare script.
///
/// Returns the script hex with the envelope removed, or the original if none found.
pub fn strip_inscription_envelope(script_hex: &str) -> String {
    match find_inscription_envelope(script_hex) {
        Some(bounds) => {
            let mut result = script_hex[..bounds.start_hex].to_string();
            result.push_str(&script_hex[bounds.end_hex..]);
            result
        }
        None => script_hex.to_string(),
    }
}

// ---------------------------------------------------------------------------
// BSV-20 (v1) -- tick-based fungible tokens
// ---------------------------------------------------------------------------

fn json_inscription(json: &str) -> Inscription {
    Inscription {
        content_type: "application/bsv-20".to_string(),
        data: utf8_to_hex(json),
    }
}

/// Build an ordered JSON object with the given key-value pairs.
/// Keys with None values are omitted.
fn build_json(entries: &[(&str, Option<&str>)]) -> String {
    let mut out = String::from("{");
    let mut first = true;
    for (key, val) in entries {
        if let Some(v) = val {
            if !first {
                out.push(',');
            }
            first = false;
            // JSON-escape key and value (simple: no special chars expected)
            out.push('"');
            out.push_str(key);
            out.push_str("\":\"");
            out.push_str(v);
            out.push('"');
        }
    }
    out.push('}');
    out
}

/// Build a BSV-20 deploy inscription.
///
/// # Arguments
/// * `tick` - Token ticker (e.g. "RUNAR")
/// * `max` - Maximum supply (e.g. "21000000")
/// * `lim` - Optional per-mint limit
/// * `dec` - Optional decimal places
pub fn bsv20_deploy(tick: &str, max: &str, lim: Option<&str>, dec: Option<&str>) -> Inscription {
    let json = build_json(&[
        ("p", Some("bsv-20")),
        ("op", Some("deploy")),
        ("tick", Some(tick)),
        ("max", Some(max)),
        ("lim", lim),
        ("dec", dec),
    ]);
    json_inscription(&json)
}

/// Build a BSV-20 mint inscription.
///
/// # Arguments
/// * `tick` - Token ticker
/// * `amt` - Amount to mint
pub fn bsv20_mint(tick: &str, amt: &str) -> Inscription {
    let json = build_json(&[
        ("p", Some("bsv-20")),
        ("op", Some("mint")),
        ("tick", Some(tick)),
        ("amt", Some(amt)),
    ]);
    json_inscription(&json)
}

/// Build a BSV-20 transfer inscription.
///
/// # Arguments
/// * `tick` - Token ticker
/// * `amt` - Amount to transfer
pub fn bsv20_transfer(tick: &str, amt: &str) -> Inscription {
    let json = build_json(&[
        ("p", Some("bsv-20")),
        ("op", Some("transfer")),
        ("tick", Some(tick)),
        ("amt", Some(amt)),
    ]);
    json_inscription(&json)
}

// ---------------------------------------------------------------------------
// BSV-21 (v2) -- ID-based fungible tokens
// ---------------------------------------------------------------------------

/// Build a BSV-21 deploy+mint inscription.
///
/// The token ID will be `<txid>_<vout>` of the output containing this
/// inscription once broadcast.
///
/// # Arguments
/// * `amt` - Amount to mint
/// * `dec` - Optional decimal places
/// * `sym` - Optional symbol
/// * `icon` - Optional icon reference
pub fn bsv21_deploy_mint(
    amt: &str,
    dec: Option<&str>,
    sym: Option<&str>,
    icon: Option<&str>,
) -> Inscription {
    let json = build_json(&[
        ("p", Some("bsv-20")),
        ("op", Some("deploy+mint")),
        ("amt", Some(amt)),
        ("dec", dec),
        ("sym", sym),
        ("icon", icon),
    ]);
    json_inscription(&json)
}

/// Build a BSV-21 transfer inscription.
///
/// # Arguments
/// * `id` - Token ID in format `<txid>_<vout>`
/// * `amt` - Amount to transfer
pub fn bsv21_transfer(id: &str, amt: &str) -> Inscription {
    let json = build_json(&[
        ("p", Some("bsv-20")),
        ("op", Some("transfer")),
        ("id", Some(id)),
        ("amt", Some(amt)),
    ]);
    json_inscription(&json)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Envelope build
    // -----------------------------------------------------------------------

    #[test]
    fn builds_text_inscription_envelope() {
        let content_type = "text/plain";
        let data = utf8_to_hex("Hello, ordinals!");
        let envelope = build_inscription_envelope(content_type, &data);

        // Starts with OP_FALSE OP_IF PUSH3 "ord" OP_1
        assert!(envelope.starts_with("0063036f726451"));
        // Ends with OP_ENDIF
        assert!(envelope.ends_with("68"));
        // Contains content type
        assert!(envelope.contains(&utf8_to_hex(content_type)));
        // Contains data
        assert!(envelope.contains(&data));
    }

    #[test]
    fn builds_envelope_with_large_data_pushdata2() {
        let content_type = "image/png";
        // 300 bytes of data, triggers OP_PUSHDATA2 (> 255 bytes)
        let data = "ff".repeat(300);
        let envelope = build_inscription_envelope(content_type, &data);

        // Should contain OP_PUSHDATA2 (4d) for the data push
        // The data is 300 bytes = 0x012c LE = 2c01
        let expected = format!("4d2c01{}", data);
        assert!(envelope.contains(&expected));
        // Still valid envelope
        assert!(envelope.starts_with("0063036f726451"));
        assert!(envelope.ends_with("68"));
    }

    #[test]
    fn builds_envelope_with_medium_data_pushdata1() {
        // 100 bytes, triggers OP_PUSHDATA1 (> 75 bytes, <= 255)
        let data = "ab".repeat(100);
        let envelope = build_inscription_envelope("application/octet-stream", &data);

        // Should contain OP_PUSHDATA1 (4c) for the data push: 100 = 0x64
        let expected = format!("4c64{}", data);
        assert!(envelope.contains(&expected));
    }

    #[test]
    fn handles_empty_data_with_op_0() {
        let envelope = build_inscription_envelope("text/plain", "");
        // Data push is OP_0 (00)
        // Pattern: ... OP_0(delimiter) OP_0(data) OP_ENDIF
        // The last bytes should be: 00 00 68
        assert!(envelope.ends_with("000068"));
    }

    // -----------------------------------------------------------------------
    // Envelope parse round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn round_trips_text_inscription() {
        let data = utf8_to_hex("Hello!");
        let envelope = build_inscription_envelope("text/plain", &data);
        let parsed = parse_inscription_envelope(&envelope).unwrap();

        assert_eq!(parsed.content_type, "text/plain");
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn round_trips_bsv20_json_inscription() {
        let json = r#"{"p":"bsv-20","op":"deploy","tick":"TEST","max":"21000000"}"#;
        let data = utf8_to_hex(json);
        let envelope = build_inscription_envelope("application/bsv-20", &data);
        let parsed = parse_inscription_envelope(&envelope).unwrap();

        assert_eq!(parsed.content_type, "application/bsv-20");
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn round_trips_large_data_pushdata2() {
        let data = "ff".repeat(300);
        let envelope = build_inscription_envelope("image/png", &data);
        let parsed = parse_inscription_envelope(&envelope).unwrap();

        assert_eq!(parsed.content_type, "image/png");
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn returns_none_for_script_without_envelope() {
        let script = format!("a914{}87", "00".repeat(20)); // P2SH-like
        assert!(parse_inscription_envelope(&script).is_none());
    }

    #[test]
    fn parses_envelope_embedded_in_larger_script() {
        let prefix = format!("a914{}8788ac", "00".repeat(20)); // some contract code
        let data = utf8_to_hex("test");
        let envelope = build_inscription_envelope("text/plain", &data);
        let suffix = format!("6a08{}", "00".repeat(8)); // OP_RETURN + state

        let full_script = format!("{}{}{}", prefix, envelope, suffix);
        let parsed = parse_inscription_envelope(&full_script).unwrap();

        assert_eq!(parsed.content_type, "text/plain");
        assert_eq!(parsed.data, data);
    }

    // -----------------------------------------------------------------------
    // Find envelope bounds
    // -----------------------------------------------------------------------

    #[test]
    fn finds_envelope_bounds_in_script() {
        let prefix = "aabb";
        let envelope = build_inscription_envelope("text/plain", &utf8_to_hex("hi"));
        let suffix = "ccdd";

        let script = format!("{}{}{}", prefix, envelope, suffix);
        let bounds = find_inscription_envelope(&script).unwrap();

        assert_eq!(bounds.start_hex, prefix.len());
        assert_eq!(bounds.end_hex, prefix.len() + envelope.len());
    }

    #[test]
    fn returns_none_when_no_envelope_present() {
        let script = format!("76a914{}88ac", "00".repeat(20));
        assert!(find_inscription_envelope(&script).is_none());
    }

    #[test]
    fn finds_envelope_between_code_and_op_return_for_stateful_scripts() {
        let code = format!("76a914{}88ac", "00".repeat(20));
        let envelope = build_inscription_envelope("text/plain", &utf8_to_hex("ord"));
        let state = format!("6a08{}", "00".repeat(8)); // OP_RETURN + 8 bytes

        let full_script = format!("{}{}{}", code, envelope, state);
        let bounds = find_inscription_envelope(&full_script).unwrap();

        assert_eq!(bounds.start_hex, code.len());
        assert_eq!(bounds.end_hex, code.len() + envelope.len());
    }

    // -----------------------------------------------------------------------
    // Strip envelope
    // -----------------------------------------------------------------------

    #[test]
    fn removes_envelope_and_preserves_surrounding_script() {
        let prefix = "aabb";
        let envelope = build_inscription_envelope("text/plain", &utf8_to_hex("hi"));
        let suffix = "ccdd";

        let stripped = strip_inscription_envelope(&format!("{}{}{}", prefix, envelope, suffix));
        assert_eq!(stripped, format!("{}{}", prefix, suffix));
    }

    #[test]
    fn returns_script_unchanged_if_no_envelope() {
        let script = format!("76a914{}88ac", "00".repeat(20));
        assert_eq!(strip_inscription_envelope(&script), script);
    }

    // -----------------------------------------------------------------------
    // BSV-20
    // -----------------------------------------------------------------------

    #[test]
    fn bsv20_deploy_inscription() {
        let inscription = bsv20_deploy("RUNAR", "21000000", Some("1000"), None);
        assert_eq!(inscription.content_type, "application/bsv-20");
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"deploy""#));
        assert!(json_str.contains(r#""tick":"RUNAR""#));
        assert!(json_str.contains(r#""max":"21000000""#));
        assert!(json_str.contains(r#""lim":"1000""#));
    }

    #[test]
    fn bsv20_deploy_without_optional_fields() {
        let inscription = bsv20_deploy("TEST", "1000", None, None);
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"deploy""#));
        assert!(json_str.contains(r#""tick":"TEST""#));
        assert!(json_str.contains(r#""max":"1000""#));
        assert!(!json_str.contains("lim"));
        assert!(!json_str.contains("dec"));
    }

    #[test]
    fn bsv20_deploy_with_decimals() {
        let inscription = bsv20_deploy("USDT", "100000000", None, Some("8"));
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""dec":"8""#));
    }

    #[test]
    fn bsv20_mint_inscription() {
        let inscription = bsv20_mint("RUNAR", "1000");
        assert_eq!(inscription.content_type, "application/bsv-20");
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"mint""#));
        assert!(json_str.contains(r#""tick":"RUNAR""#));
        assert!(json_str.contains(r#""amt":"1000""#));
    }

    #[test]
    fn bsv20_transfer_inscription() {
        let inscription = bsv20_transfer("RUNAR", "50");
        assert_eq!(inscription.content_type, "application/bsv-20");
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"transfer""#));
        assert!(json_str.contains(r#""tick":"RUNAR""#));
        assert!(json_str.contains(r#""amt":"50""#));
    }

    // -----------------------------------------------------------------------
    // BSV-21
    // -----------------------------------------------------------------------

    #[test]
    fn bsv21_deploy_mint_inscription() {
        let inscription = bsv21_deploy_mint("1000000", Some("18"), Some("RNR"), None);
        assert_eq!(inscription.content_type, "application/bsv-20");
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"deploy+mint""#));
        assert!(json_str.contains(r#""amt":"1000000""#));
        assert!(json_str.contains(r#""dec":"18""#));
        assert!(json_str.contains(r#""sym":"RNR""#));
    }

    #[test]
    fn bsv21_deploy_mint_without_optional_fields() {
        let inscription = bsv21_deploy_mint("500", None, None, None);
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"deploy+mint""#));
        assert!(json_str.contains(r#""amt":"500""#));
        assert!(!json_str.contains("dec"));
        assert!(!json_str.contains("sym"));
    }

    #[test]
    fn bsv21_transfer_inscription() {
        let inscription = bsv21_transfer(
            "3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1",
            "100",
        );
        assert_eq!(inscription.content_type, "application/bsv-20");
        let json_str = hex_to_utf8(&inscription.data);
        assert!(json_str.contains(r#""p":"bsv-20""#));
        assert!(json_str.contains(r#""op":"transfer""#));
        assert!(json_str.contains(r#""id":"3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1""#));
        assert!(json_str.contains(r#""amt":"100""#));
    }

    // -----------------------------------------------------------------------
    // Cross-check: byte-for-byte identical output to TypeScript
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_hex_matches_typescript_output() {
        // Verified against TypeScript buildInscriptionEnvelope output:
        // Test 1: text/plain + "Hello, ordinals!"
        let data1 = utf8_to_hex("Hello, ordinals!");
        let envelope1 = build_inscription_envelope("text/plain", &data1);
        assert_eq!(
            envelope1,
            "0063036f7264510a746578742f706c61696e001048656c6c6f2c206f7264696e616c732168"
        );

        // Test 2: image/png + 300 bytes of 0xff (OP_PUSHDATA2)
        let data2 = "ff".repeat(300);
        let envelope2 = build_inscription_envelope("image/png", &data2);
        assert_eq!(
            envelope2,
            format!("0063036f72645109696d6167652f706e67004d2c01{}68", data2),
        );

        // Test 3: empty data
        let envelope3 = build_inscription_envelope("text/plain", "");
        assert_eq!(envelope3, "0063036f7264510a746578742f706c61696e000068");

        // Test 4: BSV-20 JSON
        let json = r#"{"p":"bsv-20","op":"deploy","tick":"TEST","max":"21000000"}"#;
        let data4 = utf8_to_hex(json);
        let envelope4 = build_inscription_envelope("application/bsv-20", &data4);
        assert_eq!(
            envelope4,
            "0063036f726451126170706c69636174696f6e2f6273762d3230003b7b2270223a226273762d3230222c226f70223a226465706c6f79222c227469636b223a2254455354222c226d6178223a223231303030303030227d68"
        );
    }

    // -----------------------------------------------------------------------
    // Integration: envelope in RunarContract context
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_survives_embed_in_stateful_script() {
        // Simulate: code + envelope + OP_RETURN + state
        let code = "aabbccdd";
        let envelope = build_inscription_envelope("text/plain", &utf8_to_hex("test"));
        let state = format!("6a{}", "0000000000000000"); // OP_RETURN + 8-byte zero state

        let full_script = format!("{}{}{}", code, envelope, state);

        // Should find the envelope
        let bounds = find_inscription_envelope(&full_script).unwrap();
        assert_eq!(bounds.start_hex, code.len());
        assert_eq!(bounds.end_hex, code.len() + envelope.len());

        // Should parse it
        let parsed = parse_inscription_envelope(&full_script).unwrap();
        assert_eq!(parsed.content_type, "text/plain");
        assert_eq!(parsed.data, utf8_to_hex("test"));

        // Stripping should leave code + state
        let stripped = strip_inscription_envelope(&full_script);
        assert_eq!(stripped, format!("{}{}", code, state));
    }
}
