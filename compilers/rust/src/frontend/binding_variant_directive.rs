//! `@bindingVariant` directive parsing.
//!
//! A public method may carry a `/** @bindingVariant <lowS|all> */` comment
//! directive that selects the Any-S OP_PUSH_TX binding construction its
//! auto-injected covenant (and any manual `checkPreimage`) compiles to:
//!   - `lowS` (default, also when no directive is present): the branchless
//!     low-S blob, byte-identical to the pinned cross-tier binding.
//!   - `all`: the compact non-low-S blob (~45 bytes smaller), valid only for
//!     spends with nVersion != 1, where the LOW_S rule is not enforced.
//!
//! This module owns the *variant grammar* (only `lowS`/`all` accepted); the
//! *detection* lives in the parser, mirroring the TypeScript reference module
//! `packages/runar-compiler/src/passes/binding-variant-directive.ts` and the Go
//! tier's `frontend/bindingvariant_directive.go`.

/// Parse the variant token of an `@bindingVariant` directive. Only `lowS` and
/// `all` are accepted; anything else (including an empty token) is an error.
pub fn parse_binding_variant(variant_text: &str) -> Result<String, String> {
    match variant_text.trim() {
        "lowS" => Ok("lowS".to_string()),
        "all" => Ok("all".to_string()),
        other => Err(format!(
            "@bindingVariant: unknown variant \"{}\" (valid: lowS, all)",
            other
        )),
    }
}

fn has_binding_variant_token(s: &str) -> bool {
    let marker = "@bindingVariant";
    s.match_indices(marker).any(|(i, _)| {
        let after = i + marker.len();
        match s.as_bytes().get(after) {
            None => true,
            Some(c) => !(c.is_ascii_alphanumeric() || *c == b'_'),
        }
    })
}

const LINE_START_ERR: &str =
    "@bindingVariant must be a JSDoc tag at the start of a comment line (`@bindingVariant all` or `@bindingVariant lowS`)";

fn strip_comment_line(raw: &str) -> String {
    let mut s = raw.trim_start_matches([' ', '\t']);
    if let Some(rest) = s.strip_prefix("//") {
        s = rest.trim_start_matches([' ', '\t']);
    } else if let Some(rest) = s.strip_prefix("/**") {
        s = rest.trim_start_matches([' ', '\t']);
    } else if let Some(rest) = s.strip_prefix("/*") {
        s = rest.trim_start_matches([' ', '\t']);
    } else if let Some(rest) = s.strip_prefix('*') {
        s = rest.trim_start_matches([' ', '\t']);
    }
    s = s.trim_end_matches([' ', '\t']);
    if let Some(rest) = s.strip_suffix("*/") {
        s = rest.trim_end_matches([' ', '\t']);
    }
    s.to_string()
}

/// Extract and parse an `@bindingVariant` directive from a block of comment
/// text. Returns `None` when no `@bindingVariant` token is present, otherwise
/// the parse result (variant or error). Only a JSDoc/line-comment tag at the
/// start of a comment line is a directive.
pub fn extract_binding_variant_directive(comment_text: &str) -> Option<Result<String, String>> {
    if !has_binding_variant_token(comment_text) {
        return None;
    }
    for raw in comment_text.split('\n') {
        let line = strip_comment_line(raw.trim_end_matches('\r'));
        if !line.starts_with("@bindingVariant") {
            continue;
        }
        let rest = &line["@bindingVariant".len()..];
        if rest.bytes().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
            continue;
        }
        if !rest.is_empty() && rest.as_bytes()[0] != b' ' && rest.as_bytes()[0] != b'\t' {
            return Some(Err(LINE_START_ERR.to_string()));
        }
        return Some(parse_binding_variant(rest.trim()));
    }
    Some(Err(LINE_START_ERR.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lows() {
        assert_eq!(parse_binding_variant("lowS"), Ok("lowS".to_string()));
    }

    #[test]
    fn parses_all() {
        assert_eq!(parse_binding_variant("all"), Ok("all".to_string()));
    }

    #[test]
    fn rejects_unknown() {
        assert!(parse_binding_variant("high").unwrap_err().contains("unknown variant"));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_binding_variant("").unwrap_err().contains("unknown variant"));
    }

    #[test]
    fn extracts_from_jsdoc_block() {
        assert_eq!(
            extract_binding_variant_directive("* @bindingVariant all */"),
            Some(Ok("all".to_string()))
        );
    }

    #[test]
    fn extracts_lows_from_jsdoc_block() {
        assert_eq!(
            extract_binding_variant_directive("* @bindingVariant lowS "),
            Some(Ok("lowS".to_string()))
        );
    }

    #[test]
    fn extract_none_when_absent() {
        assert_eq!(extract_binding_variant_directive("* just a comment"), None);
    }
}
