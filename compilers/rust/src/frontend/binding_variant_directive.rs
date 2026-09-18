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

/// Extract and parse an `@bindingVariant` directive from a block of comment
/// text. Returns `None` when no `@bindingVariant <variant>` token is present,
/// otherwise the parse result (variant or error). Mirrors the reference regex
/// `/@bindingVariant\s+([A-Za-z0-9_]*?)(?:\*\/|\n|\r|\s|$)/`.
pub fn extract_binding_variant_directive(comment_text: &str) -> Option<Result<String, String>> {
    let idx = comment_text.find("@bindingVariant")?;
    let after = &comment_text[idx + "@bindingVariant".len()..];

    // The reference regex requires `\s+` immediately after `@bindingVariant`;
    // without leading whitespace the directive does not match (falls back to the
    // default lowS).
    let mut chars = after.char_indices();
    match chars.next() {
        Some((_, c)) if c.is_whitespace() => {}
        _ => return None,
    }

    // Skip the run of leading whitespace, then capture `[A-Za-z0-9_]*` up to the
    // first terminator (`*/`, newline, CR, whitespace, or end).
    let token_start = after
        .char_indices()
        .find(|(_, c)| !c.is_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(after.len());
    let rest = &after[token_start..];
    let mut end = rest.len();
    for (i, ch) in rest.char_indices() {
        let is_ident = ch.is_ascii_alphanumeric() || ch == '_';
        if !is_ident {
            end = i;
            break;
        }
    }
    let token = &rest[..end];

    Some(parse_binding_variant(token))
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
