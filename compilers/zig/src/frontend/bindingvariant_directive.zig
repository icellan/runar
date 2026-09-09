//! `@bindingVariant` directive parsing.
//!
//! A public method may carry a `/** @bindingVariant <VARIANT> */` comment
//! directive selecting which Any-S OP_PUSH_TX preimage-binding construction its
//! auto-injected covenant emits: "lowS" (default; low-S fixup, safe under the
//! LOW_S rule that applies to nVersion = 1) or "all" (compact non-low-S, ~50
//! bytes smaller, valid only for spends with nVersion != 1).
//!
//! The default (no directive) is "lowS" — byte-identical to the historically
//! pinned blob, so existing fixtures see ZERO change.
//!
//! Faithful port of the TypeScript reference module
//! packages/runar-compiler/src/passes/bindingvariant-directive.ts and its Go
//! peer (compilers/go/frontend/bindingvariant_directive.go).

const std = @import("std");

/// The construction used when no directive is present.
pub const BINDING_VARIANT_DEFAULT: []const u8 = "lowS";

/// Result of parsing a `@bindingVariant` value — either the canonical variant
/// name or an error message. Mirrors the sighash_directive ParseResult shape.
/// `err` is a borrowed static string OR an allocator-owned message; `value` is
/// always one of the canonical static literals ("lowS" / "all").
pub const ParseResult = union(enum) {
    value: []const u8,
    err: []const u8,
};

/// Parse the value text of a `@bindingVariant` directive.
///
/// Case-sensitive: only "lowS" and "all" are accepted, so a typo is rejected
/// rather than silently defaulted (a mis-declared binding is an exploit class).
/// When an error message must be formatted, it is allocated with `allocator`.
pub fn parseVariant(allocator: std.mem.Allocator, variant_text: []const u8) ParseResult {
    const raw = std.mem.trim(u8, variant_text, " \t\r\n");
    if (raw.len == 0) {
        return .{ .err = "@bindingVariant directive requires a value (`@bindingVariant all` or `@bindingVariant lowS`)" };
    }
    if (std.mem.eql(u8, raw, "lowS")) return .{ .value = "lowS" };
    if (std.mem.eql(u8, raw, "all")) return .{ .value = "all" };
    return .{ .err = std.fmt.allocPrint(allocator, "@bindingVariant: unknown variant '{s}' (valid: lowS, all)", .{raw}) catch "@bindingVariant: unknown variant (valid: lowS, all)" };
}

/// Extract and parse a `@bindingVariant` directive from a block of comment text.
/// Returns null when no `@bindingVariant` token is present; otherwise the parse
/// result (which may itself be an error). Mirrors the TS/Go
/// `@bindingVariant\s+([A-Za-z0-9_]*?)(?:\*\/|\n|\r|\s|$)`.
pub fn extractDirective(allocator: std.mem.Allocator, comment_text: []const u8) ?ParseResult {
    const marker = "@bindingVariant";
    const pos = std.mem.indexOf(u8, comment_text, marker) orelse return null;
    const after = pos + marker.len;
    // Match the `@bindingVariant\s+`: at least one whitespace must follow the
    // marker, otherwise `@bindingVariantType`-style identifiers are NOT directives.
    if (after >= comment_text.len or !(comment_text[after] == ' ' or comment_text[after] == '\t' or comment_text[after] == '\n' or comment_text[after] == '\r')) {
        return null;
    }
    // Collect the variant token up to `*/`, newline, carriage return, EOF, or any
    // char outside the [A-Za-z0-9_] variant alphabet (so trailing prose/space ends
    // the capture). Leading/trailing whitespace is trimmed by parseVariant.
    const rest = comment_text[after..];
    // Skip leading whitespace so the captured token starts at the variant name.
    var start: usize = 0;
    while (start < rest.len and (rest[start] == ' ' or rest[start] == '\t')) : (start += 1) {}
    var end: usize = start;
    while (end < rest.len) : (end += 1) {
        const c = rest[end];
        if (!(std.ascii.isAlphanumeric(c) or c == '_')) break;
    }
    return parseVariant(allocator, rest[start..end]);
}

// ============================================================================
// Tests — faithful port of bindingvariant-directive.test.ts (via the Go peer).
// ============================================================================

test "parseVariant accepts lowS and all" {
    const a = std.testing.allocator;
    const r1 = parseVariant(a, "lowS");
    try std.testing.expect(r1 == .value and std.mem.eql(u8, r1.value, "lowS"));
    const r2 = parseVariant(a, " all ");
    try std.testing.expect(r2 == .value and std.mem.eql(u8, r2.value, "all"));
}

test "parseVariant rejects unknown variant" {
    const a = std.testing.allocator;
    const r = parseVariant(a, "LOWS");
    try std.testing.expect(r == .err);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "unknown variant") != null);
    a.free(r.err);
}

test "parseVariant rejects empty" {
    try std.testing.expect(parseVariant(std.testing.allocator, "") == .err);
    try std.testing.expect(parseVariant(std.testing.allocator, "   ") == .err);
}

test "extractDirective JSDoc and line-comment" {
    const a = std.testing.allocator;
    const r1 = extractDirective(a, "/** @bindingVariant all */") orelse return error.MissingDirective;
    try std.testing.expect(r1 == .value and std.mem.eql(u8, r1.value, "all"));
    const r2 = extractDirective(a, "// @bindingVariant lowS") orelse return error.MissingDirective;
    try std.testing.expect(r2 == .value and std.mem.eql(u8, r2.value, "lowS"));
    try std.testing.expect(extractDirective(a, "/** no directive here */") == null);
}

test "extractDirective ignores identifier without whitespace" {
    try std.testing.expect(extractDirective(std.testing.allocator, "/** @bindingVariantType foo */") == null);
}

test "extractDirective surfaces a bad variant as an error" {
    const a = std.testing.allocator;
    const r = extractDirective(a, "/** @bindingVariant nope */") orelse return error.MissingDirective;
    try std.testing.expect(r == .err);
    a.free(r.err);
}
