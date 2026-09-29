//! `@sighash` directive parsing (issue #123).
//!
//! A public method may carry a `/** @sighash <FLAGS> */` comment directive that
//! declares which BIP-143 sighash type its auto-injected covenant (and the
//! SDK-built preimage) commits to. `<FLAGS>` is a `|`-separated set of SigHash
//! names, e.g. `SINGLE|FORKID`, `ALL|ANYONECANPAY|FORKID`, `NONE|FORKID`.
//!
//! The default (no directive) is `ALL|FORKID` (0x41) — byte-identical to the
//! historically-pinned mode, so existing fixtures see ZERO change.
//!
//! This module owns the *flag grammar* (name → value, combo validity); the
//! *detection* lives in the parser, mirroring the TypeScript reference module
//! `packages/runar-compiler/src/passes/sighash-directive.ts`.

/// Numeric value of each sighash flag name.
fn flag_value(name: &str) -> Option<i64> {
    match name {
        "ALL" => Some(0x01),
        "NONE" => Some(0x02),
        "SINGLE" => Some(0x03),
        "FORKID" => Some(0x40),
        "ANYONECANPAY" => Some(0x80),
        _ => None,
    }
}

/// True if `name` is a base-type name. Exactly one MUST appear in a directive.
fn is_base_type_name(name: &str) -> bool {
    matches!(name, "ALL" | "NONE" | "SINGLE")
}

/// SIGHASH_ALL | SIGHASH_FORKID — the default when no directive is present.
pub const SIGHASH_DEFAULT: i64 = 0x41;

/// Base-type mask. `value & BASE_TYPE_MASK` recovers 1/2/3 (ALL/NONE/SINGLE)
/// after the FORKID/ANYONECANPAY high bits are stripped.
pub const BASE_TYPE_MASK: i64 = 0x1f;
pub const BASE_ALL: i64 = 0x01;
pub const BASE_NONE: i64 = 0x02;
pub const BASE_SINGLE: i64 = 0x03;
pub const FLAG_FORKID: i64 = 0x40;
pub const FLAG_ANYONECANPAY: i64 = 0x80;

/// Parse the flag list of an `@sighash` directive.
///
/// `flags_text` is the raw text following `@sighash` (e.g. `"SINGLE|FORKID"`),
/// with any trailing comment punctuation already stripped by the caller.
///
/// Validation (security-relevant — a mis-declared mode is an exploit class):
///   - every name must be a known flag (reject typos like `FORKD`)
///   - EXACTLY ONE base type (ALL/NONE/SINGLE) — reject zero, and reject
///     nonsensical combos such as `ALL|NONE`. Checked on NAMES, not the OR-ed
///     numeric value, because `ALL|NONE` (0x01|0x02) collides with the numeric
///     value of SINGLE (0x03) — a silent, dangerous aliasing.
///   - reject a duplicated flag name (signals a copy/paste error).
///   - FORKID is mandatory on BSV: a FORKID-less flag set deploys to brick.
pub fn parse_sighash_flags(flags_text: &str) -> Result<i64, String> {
    let raw = flags_text.trim();
    if raw.is_empty() {
        return Err(
            "@sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)".to_string(),
        );
    }

    let names: Vec<&str> = raw.split('|').map(|n| n.trim()).collect();
    let mut seen: Vec<&str> = Vec::new();
    let mut base_types: Vec<&str> = Vec::new();
    let mut value: i64 = 0;

    for name in &names {
        if name.is_empty() {
            return Err(format!("@sighash directive has an empty flag in \"{}\"", raw));
        }
        let v = match flag_value(name) {
            Some(v) => v,
            None => {
                return Err(format!(
                    "@sighash: unknown flag \"{}\" (valid: ALL, NONE, SINGLE, FORKID, ANYONECANPAY)",
                    name
                ));
            }
        };
        if seen.contains(name) {
            return Err(format!("@sighash: duplicate flag \"{}\" in \"{}\"", name, raw));
        }
        seen.push(name);
        if is_base_type_name(name) {
            base_types.push(name);
        }
        value |= v;
    }

    if base_types.is_empty() {
        return Err(format!(
            "@sighash: must specify exactly one base type (ALL, NONE, or SINGLE); got \"{}\"",
            raw
        ));
    }
    if base_types.len() > 1 {
        return Err(format!(
            "@sighash: cannot combine base types ({}) — pick exactly one of ALL/NONE/SINGLE",
            base_types.join("|")
        ));
    }

    // FORKID is mandatory on BSV: the entire OP_PUSH_TX / BIP-143 preimage
    // machinery is FORKID-only, so a FORKID-less flag set deploys a covenant
    // whose derived signature can never verify (deploy-to-brick).
    if (value & FLAG_FORKID) == 0 {
        return Err(format!(
            "@sighash: FORKID is mandatory on BSV; write e.g. @sighash {}|FORKID (got \"{}\")",
            base_types[0], raw
        ));
    }

    Ok(value)
}

/// Shared diagnostics (F-039) — identical text in all seven tiers. A marker
/// that is present but not followed by a well-formed flag list, or a second
/// marker on the same method, is a compile error, never a silent fall-back to
/// the default ALL|FORKID mode.
pub const SIGHASH_MALFORMED_ERROR: &str = "@sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)";
pub const SIGHASH_MULTIPLE_ERROR: &str =
    "@sighash: more than one @sighash directive on this method; declare exactly one";

const SIGHASH_MARKER: &str = "@sighash";

/// Extract and parse an `@sighash` directive from a method's leading-comment
/// text (all of its leading comments, concatenated). Returns `None` only when
/// no `@sighash` marker is present, otherwise the parse result (value or
/// error). Mirrors the TS reference `extractSighashDirective`.
///
/// A marker is `@sighash` followed by an ASCII word boundary, so `@sighashType`
/// (or `@sighashSINGLE`) is prose, not a directive. Once a marker is present
/// (fail-closed, F-039):
///   - more than one marker is an error (`SIGHASH_MULTIPLE_ERROR`);
///   - the segment after the marker, up to `*/`, a newline, CR or the end, must
///     be empty, or start with a space/tab and contain only `[A-Za-z0-9_|]`,
///     spaces and tabs — anything else is `SIGHASH_MALFORMED_ERROR`;
///   - the flag list itself is then validated by `parse_sighash_flags`.
pub fn extract_sighash_directive(comment_text: &str) -> Option<Result<i64, String>> {
    let bytes = comment_text.as_bytes();
    let markers: Vec<usize> = comment_text
        .match_indices(SIGHASH_MARKER)
        .map(|(i, _)| i)
        .filter(|&i| {
            let next = i + SIGHASH_MARKER.len();
            next >= bytes.len() || !(bytes[next].is_ascii_alphanumeric() || bytes[next] == b'_')
        })
        .collect();
    let first = *markers.first()?;
    if markers.len() > 1 {
        return Some(Err(SIGHASH_MULTIPLE_ERROR.to_string()));
    }

    let after = &comment_text[first + SIGHASH_MARKER.len()..];
    let ab = after.as_bytes();
    let mut end = ab.len();
    for i in 0..ab.len() {
        if ab[i] == b'\n' || ab[i] == b'\r' || (ab[i] == b'*' && ab.get(i + 1) == Some(&b'/')) {
            end = i;
            break;
        }
    }
    let seg = &ab[..end];
    let is_blank = |c: u8| c == b' ' || c == b'\t';
    if !seg.is_empty()
        && !(is_blank(seg[0])
            && seg.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'|' || is_blank(c)))
    {
        return Some(Err(SIGHASH_MALFORMED_ERROR.to_string()));
    }

    Some(parse_sighash_flags(&after[..end]))
}

/// Human-readable rendering of a sighash value (for diagnostics).
pub fn describe_sighash(value: i64) -> String {
    let mut parts: Vec<String> = Vec::new();
    let base = value & BASE_TYPE_MASK;
    if base == BASE_ALL {
        parts.push("ALL".to_string());
    } else if base == BASE_NONE {
        parts.push("NONE".to_string());
    } else if base == BASE_SINGLE {
        parts.push("SINGLE".to_string());
    } else {
        parts.push(format!("0x{:x}", base));
    }
    if value & FLAG_ANYONECANPAY != 0 {
        parts.push("ANYONECANPAY".to_string());
    }
    if value & FLAG_FORKID != 0 {
        parts.push("FORKID".to_string());
    }
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_forkid() {
        assert_eq!(parse_sighash_flags("SINGLE|FORKID"), Ok(0x43));
    }

    #[test]
    fn parses_all_anyonecanpay_forkid() {
        assert_eq!(parse_sighash_flags("ALL|ANYONECANPAY|FORKID"), Ok(0xC1));
    }

    #[test]
    fn parses_default_all_forkid() {
        assert_eq!(parse_sighash_flags("ALL|FORKID"), Ok(SIGHASH_DEFAULT));
    }

    #[test]
    fn rejects_unknown_flag() {
        assert!(parse_sighash_flags("FORKD|ALL").unwrap_err().contains("unknown flag"));
    }

    #[test]
    fn rejects_all_none_alias() {
        // ALL|NONE numerically collides with SINGLE (0x03); caught on names.
        assert!(parse_sighash_flags("ALL|NONE|FORKID")
            .unwrap_err()
            .contains("cannot combine base types"));
    }

    #[test]
    fn rejects_no_base_type() {
        assert!(parse_sighash_flags("FORKID")
            .unwrap_err()
            .contains("must specify exactly one base type"));
    }

    #[test]
    fn rejects_duplicate_flag() {
        assert!(parse_sighash_flags("ALL|ALL|FORKID")
            .unwrap_err()
            .contains("duplicate flag"));
    }

    #[test]
    fn rejects_missing_forkid() {
        assert!(parse_sighash_flags("SINGLE").unwrap_err().contains("FORKID is mandatory"));
    }

    #[test]
    fn extracts_from_jsdoc_block() {
        assert_eq!(
            extract_sighash_directive("* @sighash SINGLE|FORKID "),
            Some(Ok(0x43))
        );
    }

    #[test]
    fn extract_none_when_absent() {
        assert_eq!(extract_sighash_directive("* just a comment"), None);
    }

    #[test]
    fn describe_roundtrip() {
        assert_eq!(describe_sighash(0x43), "SINGLE|FORKID");
        assert_eq!(describe_sighash(0xC1), "ALL|ANYONECANPAY|FORKID");
    }
}
