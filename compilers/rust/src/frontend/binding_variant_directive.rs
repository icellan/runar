//! `@bindingVariant` directive parsing (ports #170; original design:
//! brendan-elas, #167). Mirrors
//! packages/runar-compiler/src/passes/bindingvariant-directive.ts; diagnostic
//! text is identical in all seven tiers.
//!
//! A public `.runar.ts` method may carry `/** @bindingVariant <lowS|all> */`,
//! selecting the Any-S OP_PUSH_TX binding construction its checkPreimage
//! emits. `lowS` (default) is valid at every tx nVersion; `all` is the compact
//! non-low-S blob, spendable only when the spending tx has nVersion > 1.
//! Same marker rules as `@sighash` (F-039 / N-039): one marker per method, and
//! anything other than ` lowS` / ` all` after it is an error.

pub const BINDING_VARIANT_MARKER: &str = "@bindingVariant";

pub const BINDING_VARIANT_MALFORMED_ERROR: &str =
    "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`";
pub const BINDING_VARIANT_MULTIPLE_ERROR: &str =
    "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one";

fn parse_binding_variant(text: &str) -> Result<String, String> {
    let raw = text.trim_matches(|c| c == ' ' || c == '\t');
    match raw {
        "lowS" | "all" => Ok(raw.to_string()),
        "" => Err(BINDING_VARIANT_MALFORMED_ERROR.to_string()),
        _ => Err(format!("@bindingVariant: unknown variant \"{}\" (valid: lowS, all)", raw)),
    }
}

/// Extract and parse a `@bindingVariant` directive from a method's
/// leading-comment text. `None` only when no marker occurs.
pub fn extract_binding_variant_directive(comment_text: &str) -> Option<Result<String, String>> {
    let first = comment_text.find(BINDING_VARIANT_MARKER)?;
    let after = &comment_text[first + BINDING_VARIANT_MARKER.len()..];
    if after.contains(BINDING_VARIANT_MARKER) {
        return Some(Err(BINDING_VARIANT_MULTIPLE_ERROR.to_string()));
    }
    let bytes = after.as_bytes();
    let mut end = bytes.len();
    for i in 0..bytes.len() {
        let c = bytes[i];
        if c == b'\n' || c == b'\r' || (c == b'*' && bytes.get(i + 1) == Some(&b'/')) {
            end = i;
            break;
        }
    }
    let seg = &after[..end];
    let sb = seg.as_bytes();
    let well_formed = !sb.is_empty()
        && (sb[0] == b' ' || sb[0] == b'\t')
        && sb.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b' ' || c == b'\t');
    if !well_formed {
        return Some(Err(BINDING_VARIANT_MALFORMED_ERROR.to_string()));
    }
    Some(parse_binding_variant(seg))
}

/// The non-TS surfaces' refusal, identical in all seven tiers.
pub fn binding_variant_unsupported_message(surface_name: &str) -> String {
    format!(
        "@bindingVariant directive is not supported by the {} surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured",
        surface_name
    )
}
