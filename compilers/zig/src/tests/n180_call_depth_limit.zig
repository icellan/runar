//! N-180 — the shared call-depth limit, MAX_CALL_DEPTH = 128.
//!
//! A chain of private helpers `verify -> m0 -> m1 -> ... -> mN` is flat source
//! (MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180 this
//! tier segfaulted (stack overflow in stack_lower's inlining) on a 4000-link
//! chain, and its recursion check restarted its DFS from every method
//! (quadratic) and recursed once per link.
//!
//! Proves, on the .ts, .sol (bare `m(x)` calls) and .zig surfaces: the chain at
//! the limit (N=127, verify at depth 128) passes validation; one past (N=128) is
//! refused with the shared diagnostic naming `verify`; N=20000 is refused naming
//! `m0` without a stack overflow (which would kill this test binary); and a
//! cycle is still the recursion diagnostic, once per method that reaches it.
//! Does not prove: that the other surfaces agree, or that the accepted chain
//! compiles to the TS bytes (conformance/negatives/n180-call-depth-parity.test.ts
//! drives every CLI on all nine surfaces), nor anything about the --ir path.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const input_limits = @import("../frontend/input_limits.zig");

fn diag(w: std.mem.Allocator, m: []const u8) ![]const u8 {
    return std.fmt.allocPrint(w, "call depth of method '{s}' exceeds MAX_CALL_DEPTH (limit=128)", .{m});
}

fn chain(w: std.mem.Allocator, ext: []const u8, n: usize) ![]const u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    if (std.mem.eql(u8, ext, "ts")) {
        try b.appendSlice(w, "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
        for (0..n) |i| try b.appendSlice(w, try std.fmt.allocPrint(w, " private m{d}(x: bigint): bigint {{ return this.m{d}(x); }}\n", .{ i, i + 1 }));
        try b.appendSlice(w, try std.fmt.allocPrint(w, " private m{d}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n", .{n}));
    } else if (std.mem.eql(u8, ext, "sol")) {
        try b.appendSlice(w, "pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n");
        for (0..n) |i| try b.appendSlice(w, try std.fmt.allocPrint(w, " function m{d}(int x) private returns (int) {{ return m{d}(x); }}\n", .{ i, i + 1 }));
        try b.appendSlice(w, try std.fmt.allocPrint(w, " function m{d}(int x) private returns (int) {{ return x; }}\n function verify(int a) public {{ require(m0(a) == t); }}\n}}\n", .{n}));
    } else {
        try b.appendSlice(w, "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    t: i64,\n    pub fn init(t: i64) P { return .{ .t = t }; }\n");
        for (0..n) |i| try b.appendSlice(w, try std.fmt.allocPrint(w, "    fn m{d}(self: *const P, x: i64) i64 {{ return self.m{d}(x); }}\n", .{ i, i + 1 }));
        try b.appendSlice(w, try std.fmt.allocPrint(w, "    fn m{d}(self: *const P, x: i64) i64 {{ return x; }}\n    pub fn verify(self: *const P, a: i64) void {{ runar.assert(self.m0(a) == self.t); }}\n}};\n", .{n}));
    }
    return b.items;
}

/// The validator's error messages for `src`.
fn errorsOf(w: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const []const u8 {
    const parsed = compiler_api.parseSource(w, src, file_name);
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const result = try compiler_api.validateForFile(w, parsed.contract orelse return error.TestFixtureDidNotParse, file_name);
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    for (result.errors) |e| try out.append(w, e.message);
    return out.items;
}

fn expectOnly(got: []const []const u8, want: []const u8) !void {
    if (got.len != 1 or !std.mem.eql(u8, got[0], want)) {
        std.debug.print("  want exactly [{s}], got {d} error(s):\n", .{ want, got.len });
        for (got) |g| std.debug.print("    {s}\n", .{g});
        return error.CallDepthDiagnosticMismatch;
    }
}

test "N-180: MAX_CALL_DEPTH is 128" {
    try std.testing.expectEqual(@as(usize, 128), input_limits.MAX_CALL_DEPTH);
}

test "N-180: chain boundary and a 20000-link chain on .ts, .sol, .zig" {
    for ([_][]const u8{ "ts", "sol", "zig" }) |ext| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const file = try std.fmt.allocPrint(w, "P.runar.{s}", .{ext});

        const at = try errorsOf(w, try chain(w, ext, 127), file);
        if (at.len != 0) {
            for (at) |g| std.debug.print("  {s} N=127 refused: {s}\n", .{ ext, g });
            return error.AtLimitRefused;
        }
        try expectOnly(try errorsOf(w, try chain(w, ext, 128), file), try diag(w, "verify"));
        try expectOnly(try errorsOf(w, try chain(w, ext, 20000), file), try diag(w, "m0"));
    }
}

test "N-180: a cycle is still reported as recursion, once per method that reaches it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();
    const src =
        \\import { SmartContract, assert } from 'runar-lang';
        \\class P extends SmartContract {
        \\ readonly t: bigint;
        \\ constructor(t: bigint) { super(t); this.t = t; }
        \\ private a(x: bigint): bigint { return this.b(x); }
        \\ private b(x: bigint): bigint { return this.c(x); }
        \\ private c(x: bigint): bigint { return this.b(x); }
        \\ private d(x: bigint): bigint { return x; }
        \\ public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }
        \\}
    ;
    const got = try errorsOf(w, src, "P.runar.ts");
    try std.testing.expectEqual(@as(usize, 4), got.len);
    for (got) |g| try std.testing.expectEqualStrings("recursion detected: method calls itself directly or indirectly", g);
}
