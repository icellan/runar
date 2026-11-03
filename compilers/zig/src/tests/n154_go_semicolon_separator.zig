//! N-154 — a .runar.go `;` that separates statements on one line is accepted
//! (user decision R56: it is valid Go), byte-identical to the newline form.
//! An empty statement stays refused (N-153). Port of the Zig rows of
//! conformance/negatives/n154-go-semicolon-separator-parity.test.ts.
//!
//! Pre-fix the Zig tier refused every same-line `;` (ParseFailed) while the
//! Go, Rust, Python and Java tiers compiled it.
//!
//! Proves: in the Zig tier, each same-line `;` form compiles to the hex of its
//! newline form in both constant-folding modes, and `;;`, `; ;`, `{;` and a
//! `;` on the line after a bare `return` are refused with the TS diagnostic
//! "Unexpected token in expression: ';'".
//! Does NOT prove: the other six tiers (the conformance test does).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const HEAD =
    \\package contract
    \\
    \\import runar "github.com/icellan/runar/packages/runar-go"
    \\
    \\type Disc struct {
    \\    runar.SmartContract
    \\    T runar.Bigint `runar:"readonly"`
    \\}
    \\
    \\func (c *Disc) Unlock(x runar.Bigint) {
    \\
;
const MID =
    \\
    \\}
    \\
    \\func (c *Disc) guard(x runar.Bigint) {
    \\
;
const TAIL =
    \\
    \\}
    \\
;
const GUARD = "\trunar.Assert(x > 0)";

fn hexOf(src: []const u8, fold_off: bool) ![]const u8 {
    const r = try compiler_api.compileSourceWithOptions(std.testing.allocator, src, "Disc.runar.go", fold_off);
    defer if (r.artifact_json) |j| std.testing.allocator.free(j);
    defer {
        for (r.warnings) |line| std.testing.allocator.free(line);
        std.testing.allocator.free(r.warnings);
    }
    return r.script_hex;
}

fn expectSame(comptime newline: []const u8, comptime semi: []const u8, comptime g_newline: []const u8, comptime g_semi: []const u8) !void {
    for ([_]bool{ false, true }) |fold_off| {
        const want = try hexOf(HEAD ++ newline ++ MID ++ g_newline ++ TAIL, fold_off);
        defer std.testing.allocator.free(want);
        const got = hexOf(HEAD ++ semi ++ MID ++ g_semi ++ TAIL, fold_off) catch |e| {
            std.debug.print("go `{s}` (fold-off={}) was refused\n", .{ semi, fold_off });
            return e;
        };
        defer std.testing.allocator.free(got);
        std.testing.expectEqualStrings(want, got) catch |e| {
            std.debug.print("go `{s}` (fold-off={}) diverged from its newline form\n", .{ semi, fold_off });
            return e;
        };
    }
}

fn expectRefused(comptime stmt: []const u8, comptime guard: []const u8) !void {
    const want = "Unexpected token in expression: ';'";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: compiler_api.Diagnostics = .{};
    if (compiler_api.runPipeline(arena.allocator(), HEAD ++ stmt ++ MID ++ guard ++ TAIL, "Disc.runar.go", .{ .disable_constant_folding = true }, &diag)) |_| {
        std.debug.print("go `{s}` compiled, expected a refusal\n", .{stmt});
        return error.ShapeCompiled;
    } else |_| {}
    for (diag.errors.items) |line| {
        if (std.mem.indexOf(u8, line, want) != null) return;
    }
    std.debug.print("go `{s}`: want \"{s}\", got:\n", .{ stmt, want });
    for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
    return error.WrongDiagnostic;
}

test "N-154: two statements on one line match the newline form" {
    try expectSame("\ta := x + 1\n\tb := a + 2\n\trunar.Assert(b == c.T)", "\ta := x + 1; b := a + 2\n\trunar.Assert(b == c.T)", GUARD, GUARD);
}

test "N-154: a trailing `;` on the last statement matches the newline form" {
    try expectSame("\trunar.Assert(x == c.T)", "\trunar.Assert(x == c.T);", GUARD, GUARD);
}

test "N-154: `;` in and after if / else arms matches the newline form" {
    try expectSame(
        "\ty := x\n\tif y > 1 {\n\t\ty = y - 1\n\t} else {\n\t\ty = y + 1\n\t}\n\trunar.Assert(y == c.T)",
        "\ty := x; if y > 1 { y = y - 1; } else { y = y + 1; }; runar.Assert(y == c.T)",
        GUARD,
        GUARD,
    );
}

test "N-154: `;` in and after a for body matches the newline form" {
    try expectSame(
        "\ts := x\n\tfor i := 0; i < 3; i++ {\n\t\ts += i\n\t}\n\trunar.Assert(s == c.T)",
        "\ts := x; for i := 0; i < 3; i++ { s += i; }; runar.Assert(s == c.T)",
        GUARD,
        GUARD,
    );
}

test "N-154: a bare `return;` matches the newline form" {
    try expectSame("\tc.guard(x)\n\trunar.Assert(x == c.T)", "\tc.guard(x); runar.Assert(x == c.T)", "\trunar.Assert(x > 0)\n\treturn", "\trunar.Assert(x > 0); return;");
}

test "N-154: empty statements next to a separator stay refused with the TS diagnostic" {
    try expectRefused("\trunar.Assert(x == c.T);;", GUARD);
    try expectRefused("\ta := x; ;\n\trunar.Assert(a == c.T)", GUARD);
    try expectRefused("\tif x == c.T {; runar.Assert(true) }\n\trunar.Assert(true)", GUARD);
    try expectRefused("\tc.guard(x)\n\trunar.Assert(x == c.T)", "\trunar.Assert(x > 0)\n\treturn\n\t;");
}
