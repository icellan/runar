//! F-039 — a present-but-malformed `@sighash` marker is a compile error.
//!
//! Before F-039 the Zig extractor stopped the flag capture at the first
//! character outside the flag alphabet, so `/** @sighash SINGLE|FORKID! */`
//! was silently read as `SINGLE|FORKID` — while the TS reference read the same
//! text as NO directive (default ALL|FORKID). Neither refused it. It also
//! looked only at the FIRST `@sighash` substring (no word boundary), and a
//! second directive on one method was silently ignored.
//!
//! Proves: the Zig TS-surface parser refuses each malformed / duplicated shape
//! with the diagnostic shared by all seven tiers (N-039: including `@sighash`
//! glued to the next token, located at the method declaration), and still
//! honours a well-formed multi-line JSDoc directive.
//! Does not prove: cross-tier agreement (conformance/negatives rejection-parity).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");

const MALFORMED = "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)";
const MULTIPLE = "Method 'bump': @sighash: more than one @sighash directive on this method; declare exactly one";
const EMPTY = "Method 'bump': @sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)";

fn src(comptime directive: []const u8) []const u8 {
    return "class C extends StatefulSmartContract {\n" ++
        "  n: bigint;\n" ++
        "  constructor(n: bigint) { super(n); this.n = n; }\n" ++
        "  " ++ directive ++ "\n" ++
        "  public bump(): void { this.addOutput(1000n, this.n); }\n" ++
        "}\n";
}

/// Parse and require exactly one error whose message (after the
/// `file:line:col: ` prefix) is exactly `want`.
fn expectSoleError(comptime directive: []const u8, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = parse_ts.parseTs(arena.allocator(), src(directive), "X.runar.ts");
    if (parsed.errors.len != 1 or !std.mem.endsWith(u8, parsed.errors[0], want)) {
        std.debug.print("directive {s}: got {d} error(s):\n", .{ directive, parsed.errors.len });
        for (parsed.errors) |e| std.debug.print("  {s}\n", .{e});
        return error.TestExpectedSoleError;
    }
    const prefix = parsed.errors[0][0 .. parsed.errors[0].len - want.len];
    try std.testing.expect(std.mem.endsWith(u8, prefix, ": "));
}

fn sighashOf(comptime directive: []const u8) !?i32 {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = parse_ts.parseTs(arena.allocator(), src(directive), "X.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    for (parsed.contract.?.methods) |m| {
        if (std.mem.eql(u8, m.name, "bump")) return m.sighash_type;
    }
    return error.MethodNotFound;
}

test "F-039 malformed @sighash directive is rejected, not defaulted" {
    try expectSoleError("/** @sighash SINGLE|FORKID! */", MALFORMED);
    try expectSoleError("/** @sighash:SINGLE|FORKID */", MALFORMED);
    try expectSoleError("// @sighash=SINGLE|FORKID", MALFORMED);
    try expectSoleError("/** @sighash SINGLE,FORKID */", MALFORMED);
}

test "F-039 bare @sighash marker on a line comment is rejected" {
    try expectSoleError("// @sighash", EMPTY);
}

test "F-039 more than one @sighash directive on a method is rejected" {
    try expectSoleError("/** @sighash SINGLE|FORKID\n   * @sighash ALL|FORKID */", MULTIPLE);
    try expectSoleError("/** @sighash SINGLE|FORKID */\n  /** @sighash ALL|FORKID */", MULTIPLE);
    try expectSoleError("/** @sighash SINGLE|FORKID!\n   * @sighash NONE|FORKID */", MULTIPLE);
}

// N-039 (user decision R85, "Refuse, all 7 tiers"): this used to pin the
// word-boundary rule (`@sighashSINGLE` / `@sighashType` read as prose, so the
// method silently got the default ALL|FORKID). A comment token that starts
// with `@sighash` but is not exactly `@sighash <FLAGS>` is now refused with the
// shared malformed diagnostic; the case list is unchanged plus `_` / digit.
test "N-039 @sighash glued to the next token is rejected, not prose" {
    try expectSoleError("/** @sighashSINGLE|FORKID */", MALFORMED);
    try expectSoleError("/** see the @sighashType docs */", MALFORMED);
    try expectSoleError("// @sighash_SINGLE|FORKID", MALFORMED);
    try expectSoleError("/** @sighash2 */", MALFORMED);
}

// N-039 (R88a): the diagnostic sits at the method declaration (`public` on
// line 5, 0-based column 2), like the TS reference; Zig used to report the
// token after the method body.
test "N-039 @sighash diagnostic is located at the method declaration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = parse_ts.parseTs(arena.allocator(), src("/** @sighashSINGLE|FORKID */"), "X.runar.ts");
    try std.testing.expectEqual(@as(usize, 1), parsed.errors.len);
    try std.testing.expect(std.mem.startsWith(u8, parsed.errors[0], "X.runar.ts:5:2: Method 'bump': "));
}

test "F-039 well-formed multi-line JSDoc directive still honoured" {
    try std.testing.expectEqual(@as(?i32, 0x43), try sighashOf("/**\n   * Bump.\n   * @sighash SINGLE|FORKID\n   */"));
}
