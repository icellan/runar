//! `@bindingVariant` directive parsing (ports #170; original design:
//! brendan-elas, #167). Mirrors
//! packages/runar-compiler/src/passes/bindingvariant-directive.ts; diagnostic
//! text is identical in all seven tiers.
//!
//! A public `.runar.ts` method may carry `/** @bindingVariant <lowS|all> */`,
//! selecting the Any-S OP_PUSH_TX binding construction its checkPreimage
//! emits. `lowS` (default) is valid at every tx nVersion; `all` is the compact
//! non-low-S blob, spendable only when the spending tx has nVersion > 1. Same
//! marker rules as `@sighash` (F-039 / N-039): one marker per method, and
//! anything other than ` lowS` / ` all` after it is an error.

const std = @import("std");

pub const MARKER = "@bindingVariant";

pub const MALFORMED_ERROR = "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`";
pub const MULTIPLE_ERROR = "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one";
pub const LOST_ERROR = "@bindingVariant directive is not attached to any method and would be silently ignored; put the comment on its own line directly above the method it annotates (a comment that shares a line with the preceding code belongs to that code)";

/// The parse result: `.all` is true for `all`, false for `lowS`.
pub const ParseResult = union(enum) {
    all: bool,
    err: []const u8,
};

fn isSegByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == ' ' or c == '\t';
}

/// Extract and parse a `@bindingVariant` directive from a method's
/// leading-comment text. Null only when no marker occurs. The `unknown
/// variant` message is allocated with `allocator`.
pub fn extractDirective(allocator: std.mem.Allocator, comment_text: []const u8) ?ParseResult {
    const first = std.mem.indexOf(u8, comment_text, MARKER) orelse return null;
    const rest = comment_text[first + MARKER.len ..];
    if (std.mem.indexOf(u8, rest, MARKER) != null) return .{ .err = MULTIPLE_ERROR };
    var end: usize = rest.len;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const c = rest[i];
        if (c == '\n' or c == '\r' or (c == '*' and i + 1 < rest.len and rest[i + 1] == '/')) {
            end = i;
            break;
        }
    }
    const seg = rest[0..end];
    if (seg.len == 0 or !(seg[0] == ' ' or seg[0] == '\t')) return .{ .err = MALFORMED_ERROR };
    for (seg) |c| if (!isSegByte(c)) return .{ .err = MALFORMED_ERROR };
    const raw = std.mem.trim(u8, seg, " \t");
    if (std.mem.eql(u8, raw, "all")) return .{ .all = true };
    if (std.mem.eql(u8, raw, "lowS")) return .{ .all = false };
    if (raw.len == 0) return .{ .err = MALFORMED_ERROR };
    const msg = std.fmt.allocPrint(allocator, "@bindingVariant: unknown variant \"{s}\" (valid: lowS, all)", .{raw}) catch return .{ .err = MALFORMED_ERROR };
    return .{ .err = msg };
}

/// The non-TS surfaces' refusal for `surface` ("Solidity", "Go DSL", ...),
/// identical in all seven tiers.
pub fn unsupportedError(comptime surface: []const u8) []const u8 {
    return "@bindingVariant directive is not supported by the " ++ surface ++ " surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured";
}

test "extractDirective" {
    const a = std.testing.allocator;
    try std.testing.expect(extractDirective(a, "/** @sighash ALL|FORKID */") == null);
    try std.testing.expectEqual(true, extractDirective(a, "/** @bindingVariant all */").?.all);
    try std.testing.expectEqual(false, extractDirective(a, "// @bindingVariant lowS").?.all);
    try std.testing.expectEqualStrings(MALFORMED_ERROR, extractDirective(a, "/** @bindingVariant: all */").?.err);
    try std.testing.expectEqualStrings(MULTIPLE_ERROR, extractDirective(a, "/** @bindingVariant all */\n// @bindingVariant lowS").?.err);
    const unknown = extractDirective(a, "/** @bindingVariant high */").?.err;
    defer a.free(unknown);
    try std.testing.expectEqualStrings("@bindingVariant: unknown variant \"high\" (valid: lowS, all)", unknown);
}
