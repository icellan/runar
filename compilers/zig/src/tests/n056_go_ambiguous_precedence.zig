//! N-056 (CL-BUG-192) — `.runar.go` operator precedence differed across tiers.
//!
//! The Go tier parses `.runar.go` with go/parser (Go precedence); this tier,
//! the TS reference and the other four use the C ladder, so `a & b + 1` was
//! `(a & b) + 1` in one tier and `a & (b + 1)` in the rest. R51: every tier
//! refuses an unparenthesised mix whose grouping differs between the two
//! schemes, with the shared diagnostic from 01-parse-go.ts.
//!
//! The oracle recomputes the 72 ambiguous ordered operator pairs from the two
//! precedence tables rather than reusing the parser's constant.
//!
//! What this proves: this tier refuses every ambiguous pair with the shared
//! text, accepts the 252 agreeing pairs and both parenthesisations, and treats
//! `&^` as `&` and call results as operands.
//! What it does not prove: emitted bytes or the other tiers (conformance
//! negatives N175-N179 and the agreeing-pairs control cover cross-tier
//! agreement).

const std = @import("std");
const testing = std.testing;
const parse_go = @import("../passes/parse_go.zig");

const Op = struct { s: []const u8, go: u8, c: u8 };

const ops = [_]Op{
    .{ .s = "*", .go = 5, .c = 10 },  .{ .s = "/", .go = 5, .c = 10 },  .{ .s = "%", .go = 5, .c = 10 },
    .{ .s = "<<", .go = 5, .c = 8 },  .{ .s = ">>", .go = 5, .c = 8 },  .{ .s = "&", .go = 5, .c = 5 },
    .{ .s = "+", .go = 4, .c = 9 },   .{ .s = "-", .go = 4, .c = 9 },   .{ .s = "|", .go = 4, .c = 3 },
    .{ .s = "^", .go = 4, .c = 4 },   .{ .s = "==", .go = 3, .c = 6 },  .{ .s = "!=", .go = 3, .c = 6 },
    .{ .s = "<", .go = 3, .c = 7 },   .{ .s = "<=", .go = 3, .c = 7 },  .{ .s = ">", .go = 3, .c = 7 },
    .{ .s = ">=", .go = 3, .c = 7 },  .{ .s = "&&", .go = 2, .c = 2 },  .{ .s = "||", .go = 1, .c = 1 },
};

fn source(allocator: std.mem.Allocator, expr: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\package contract
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Probe struct {{
        \\    runar.SmartContract
        \\    T runar.Int `runar:"readonly"`
        \\}}
        \\
        \\func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {{
        \\    x := {s}
        \\    runar.Assert(x == c.T)
        \\}}
        \\
    , .{expr});
}

fn message(allocator: std.mem.Allocator, x: []const u8, y: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "ambiguous operator precedence in .runar.go: `a {s} b {s} c` groups differently " ++
        "under Go precedence than in Rúnar's other surfaces; add parentheses", .{ x, y });
}

fn errorsOf(allocator: std.mem.Allocator, expr: []const u8) ![]const []const u8 {
    return parse_go.parseGo(allocator, try source(allocator, expr), "Probe.runar.go").errors;
}

fn refused(allocator: std.mem.Allocator, expr: []const u8, x: []const u8, y: []const u8) !bool {
    const want = try message(allocator, x, y);
    for (try errorsOf(allocator, expr)) |e| {
        if (std.mem.indexOf(u8, e, want) != null) return true;
    }
    std.debug.print("N-056: `{s}` not refused\n", .{expr});
    return false;
}

fn accepted(allocator: std.mem.Allocator, expr: []const u8) !bool {
    const errs = try errorsOf(allocator, expr);
    if (errs.len == 0) return true;
    std.debug.print("N-056: `{s}` unexpected error: {s}\n", .{ expr, errs[0] });
    return false;
}

test "N-056: every ambiguous pair refused, every agreeing pair accepted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var conflicts: usize = 0;
    var agree: usize = 0;
    var failures: usize = 0;
    for (ops) |x| {
        for (ops) |y| {
            const expr = try std.fmt.allocPrint(a, "a {s} b {s} d", .{ x.s, y.s });
            if ((x.go >= y.go) != (x.c >= y.c)) {
                conflicts += 1;
                if (!try refused(a, expr, x.s, y.s)) failures += 1;
                if (!try accepted(a, try std.fmt.allocPrint(a, "(a {s} b) {s} d", .{ x.s, y.s }))) failures += 1;
                if (!try accepted(a, try std.fmt.allocPrint(a, "a {s} (b {s} d)", .{ x.s, y.s }))) failures += 1;
            } else {
                agree += 1;
                if (!try accepted(a, expr)) failures += 1;
            }
        }
    }
    try testing.expectEqual(@as(usize, 72), conflicts);
    try testing.expectEqual(@as(usize, 252), agree);
    try testing.expectEqual(@as(usize, 0), failures);
}

test "N-056: probes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var failures: usize = 0;
    if (!try refused(a, "a & b + 1", "&", "+")) failures += 1;
    if (!try refused(a, "a + b << 2", "+", "<<")) failures += 1;
    if (!try refused(a, "a | b + d", "|", "+")) failures += 1;
    if (!try refused(a, "a & 255 == 15", "&", "==")) failures += 1;
    if (!try accepted(a, "a ^ b * d")) failures += 1;
    if (!try refused(a, "(a & b + 1) * d", "&", "+")) failures += 1;
    if (!try refused(a, "runar.Abs(a + b << 2)", "+", "<<")) failures += 1;
    if (!try refused(a, "a * (d + (a | b + d))", "|", "+")) failures += 1;
    if (!try accepted(a, "a + b * d - a")) failures += 1;
    if (!try refused(a, "a * b + d << 1", "+", "<<")) failures += 1;
    if (!try accepted(a, "a &^ b")) failures += 1;
    if (!try refused(a, "a &^ b + d", "&", "+")) failures += 1;
    if (!try accepted(a, "(a &^ b) + d")) failures += 1;
    if (!try accepted(a, "runar.BigintBigAdd(a, b) << 2")) failures += 1;
    if (!try accepted(a, "runar.Abs(a + b) << 2")) failures += 1;
    if (!try refused(a, "-a + b << 2", "+", "<<")) failures += 1;
    if (!try accepted(a, "-(a + b) << 2")) failures += 1;
    try testing.expectEqual(@as(usize, 0), failures);
}
