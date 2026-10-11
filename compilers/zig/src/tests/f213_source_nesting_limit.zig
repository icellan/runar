//! F-213 — one shared source-nesting limit, MAX_SOURCE_NESTING = 128, on all
//! nine surfaces of this tier. Zig-tier port of
//! packages/runar-compiler/src/__tests__/f213-source-nesting-limit.test.ts.
//!
//! Pre-fix, MAX_SOURCE_BYTES (4 MiB) was the only input bound. The parsers
//! carried a private `expression nesting depth exceeds maximum (256)` counter
//! on parseExpression alone, so nested statements recursed without bound
//! (20,000 nested `if`s segfaulted the CLI in the parser) and a left-deep
//! `a + a + ...` chain, built by a loop, segfaulted the first recursive pass
//! over it (validate.zig, or the Solidity parser's own bare-property pass).
//!
//! What this proves, per surface (.runar.{ts,sol,move,go,rs,py,zig,rb,java}),
//! for the four canonical shapes of the spec — `result = ((..(value)..))`,
//! n nested `if (mode) { .. }`, `result = -(-(..-(value)..))` and a k-term
//! `value + value + ...` chain:
//!   * the at-limit source compiles end to end (parens n=126, nested-if
//!     n=126, unary n=63, chain k=127);
//!   * the one-past source is refused with exactly the shared diagnostic
//!     `source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)`
//!     (parens n=127, nested-if n=127, unary n=64, chain k=128);
//!   * the n=20,000 shapes (nested-if n=2,500 on .runar.py, where deeper
//!     indentation passes MAX_SOURCE_BYTES) are refused with that diagnostic
//!     and do not crash this process — through `runPipeline` and directly
//!     through the per-format exported parse entry;
//!   * the constant is 128.
//! What it does NOT prove: that the accepted scripts are byte-identical to
//! the other tiers' (the F-213 boundary harness and the conformance suite do
//! that), the 500,000-term chain (harness only: a 4 MB source per surface is
//! too slow for a Debug unit test), or any shape other than these four.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const input_limits = @import("../frontend/input_limits.zig");
const parse_ts = @import("../passes/parse_ts.zig");
const parse_sol = @import("../passes/parse_sol.zig");
const parse_move = @import("../passes/parse_move.zig");
const parse_go = @import("../passes/parse_go.zig");
const parse_rust = @import("../passes/parse_rust.zig");
const parse_python = @import("../passes/parse_python.zig");
const parse_zig = @import("../passes/parse_zig.zig");
const parse_ruby = @import("../passes/parse_ruby.zig");
const parse_java = @import("../passes/parse_java.zig");

const DIAG = "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)";

const Shape = enum { parens, nested_if, neg, chain };

const Surface = struct {
    ext: []const u8,
    head: []const u8,
    /// Statement prefix / suffix around `result = <expr>`.
    pre: []const u8,
    post: []const u8,
    if_open: []const u8,
    if_close: []const u8,
    python_indent: bool = false,
};

const SURFACES = [_]Surface{
    .{
        .ext = "ts",
        .head = "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
        .pre = "    result = ",
        .post = ";",
        .if_open = "if (mode) {\n",
        .if_close = "}\n",
    },
    .{
        .ext = "sol",
        .head = "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n",
        .pre = "        result = ",
        .post = ";",
        .if_open = "if (mode) {\n",
        .if_close = "}\n",
    },
    .{
        .ext = "move",
        .head = "module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n",
        .pre = "        result = ",
        .post = ";",
        .if_open = "if (mode) {\n",
        .if_close = "};\n",
    },
    .{
        .ext = "go",
        .head = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n",
        .pre = "\tresult = ",
        .post = "",
        .if_open = "if mode {\n",
        .if_close = "}\n",
    },
    .{
        .ext = "rs",
        .head = "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n",
        .pre = "        result = ",
        .post = ";",
        .if_open = "if mode {\n",
        .if_close = "}\n",
    },
    .{
        .ext = "py",
        .head = "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n",
        .pre = "        result = ",
        .post = "",
        .if_open = "",
        .if_close = "",
        .python_indent = true,
    },
    .{
        .ext = "zig",
        .head = "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n",
        .pre = "        result = ",
        .post = ";",
        .if_open = "if (mode) {\n",
        .if_close = "}\n",
    },
    .{
        .ext = "rb",
        .head = "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
        .pre = "    result = ",
        .post = "",
        .if_open = "if mode\n",
        .if_close = "end\n",
    },
    .{
        .ext = "java",
        .head = "package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n",
        .pre = "        result = ",
        .post = ";",
        .if_open = "if (mode) {\n",
        .if_close = "}\n",
    },
};

fn repeat(out: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, s: []const u8, n: usize) !void {
    for (0..n) |_| try out.appendSlice(a, s);
}

/// The source of `shape` at size `n` on `sf` — byte-identical to what the
/// F-213 harness generator (gen.py) writes.
fn source(a: std.mem.Allocator, sf: Surface, shape: Shape, n: usize) ![]const u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    if (shape == .nested_if) {
        const stmt = std.mem.trimStart(u8, sf.pre, " \t");
        if (sf.python_indent) {
            for (0..n) |i| {
                try body.appendSlice(a, "        ");
                try body.appendNTimes(a, ' ', i);
                try body.appendSlice(a, "if mode:\n");
            }
            try body.appendSlice(a, "        ");
            try body.appendNTimes(a, ' ', n);
            try body.appendSlice(a, stmt);
            try body.appendSlice(a, "value");
        } else {
            try repeat(&body, a, sf.if_open, n);
            try body.appendSlice(a, stmt);
            try body.appendSlice(a, "value");
            try body.appendSlice(a, sf.post);
            try body.appendSlice(a, "\n");
            try repeat(&body, a, sf.if_close, n);
        }
    } else {
        try body.appendSlice(a, sf.pre);
        switch (shape) {
            .parens => {
                try body.appendNTimes(a, '(', n);
                try body.appendSlice(a, "value");
                try body.appendNTimes(a, ')', n);
            },
            .neg => {
                try repeat(&body, a, "-(", n);
                try body.appendSlice(a, "value");
                try body.appendNTimes(a, ')', n);
            },
            .chain => {
                for (0..n) |i| {
                    if (i > 0) try body.appendSlice(a, " + ");
                    try body.appendSlice(a, "value");
                }
            },
            .nested_if => unreachable,
        }
        try body.appendSlice(a, sf.post);
    }
    return std.mem.replaceOwned(u8, a, sf.head, "{BODY}", body.items);
}

fn fileName(a: std.mem.Allocator, sf: Surface) ![]const u8 {
    return std.fmt.allocPrint(a, "P.runar.{s}", .{sf.ext});
}

fn hasDiag(lines: []const []const u8) bool {
    for (lines) |l| if (std.mem.indexOf(u8, l, DIAG) != null) return true;
    return false;
}

fn expectAccept(sf: Surface, shape: Shape, n: usize) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try source(a, sf, shape, n);
    var diag: compiler_api.Diagnostics = .{};
    _ = compiler_api.runPipeline(a, src, try fileName(a, sf), .{}, &diag) catch |err| {
        std.debug.print("F-213 {s} {s} n={d}: want ACCEPT, got {s}\n", .{ sf.ext, @tagName(shape), n, @errorName(err) });
        for (diag.errors.items) |e| std.debug.print("  {s}\n", .{e});
        return error.TestExpectedAccept;
    };
}

fn expectRefuse(sf: Surface, shape: Shape, n: usize) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try source(a, sf, shape, n);
    var diag: compiler_api.Diagnostics = .{};
    if (compiler_api.runPipeline(a, src, try fileName(a, sf), .{}, &diag)) |_| {
        std.debug.print("F-213 {s} {s} n={d}: want REFUSE, but it compiled\n", .{ sf.ext, @tagName(shape), n });
        return error.TestExpectedRefusal;
    } else |_| {}
    if (!hasDiag(diag.errors.items)) {
        std.debug.print("F-213 {s} {s} n={d}: refused without the shared diagnostic:\n", .{ sf.ext, @tagName(shape), n });
        for (diag.errors.items) |e| std.debug.print("  {s}\n", .{e});
        return error.TestExpectedDiagnostic;
    }
}

/// The per-format exported entry the dispatcher calls (N-136 guards it too).
fn parseDirect(a: std.mem.Allocator, sf: Surface, src: []const u8, file: []const u8) []const []const u8 {
    const ext = sf.ext;
    if (std.mem.eql(u8, ext, "ts")) return parse_ts.parseTs(a, src, file).errors;
    if (std.mem.eql(u8, ext, "sol")) return parse_sol.parseSol(a, src, file).errors;
    if (std.mem.eql(u8, ext, "move")) return parse_move.parseMove(a, src, file).errors;
    if (std.mem.eql(u8, ext, "go")) return parse_go.parseGo(a, src, file).errors;
    if (std.mem.eql(u8, ext, "rs")) return parse_rust.parseRust(a, src, file).errors;
    if (std.mem.eql(u8, ext, "py")) return parse_python.parsePython(a, src, file).errors;
    if (std.mem.eql(u8, ext, "zig")) return parse_zig.parseZig(a, src, file).errors;
    if (std.mem.eql(u8, ext, "rb")) return parse_ruby.parseRuby(a, src, file).errors;
    return parse_java.parseJava(a, src, file).errors;
}

fn expectDeepRefused(sf: Surface, shape: Shape, n: usize) !void {
    try expectRefuse(sf, shape, n);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try source(a, sf, shape, n);
    const errs = parseDirect(a, sf, src, try fileName(a, sf));
    if (!hasDiag(errs)) {
        std.debug.print("F-213 {s} {s} n={d}: per-format entry refused without the shared diagnostic:\n", .{ sf.ext, @tagName(shape), n });
        for (errs) |e| std.debug.print("  {s}\n", .{e});
        return error.TestExpectedDiagnostic;
    }
}

test "F-213 MAX_SOURCE_NESTING is 128 and the diagnostic names it" {
    try std.testing.expectEqual(@as(u32, 128), input_limits.MAX_SOURCE_NESTING);
    try std.testing.expectEqualStrings(DIAG, input_limits.SOURCE_NESTING_MESSAGE);
}

test "F-213 parens: n=126 accepted, n=127 refused, on every surface" {
    for (SURFACES) |sf| {
        try expectAccept(sf, .parens, 126);
        try expectRefuse(sf, .parens, 127);
    }
}

test "F-213 nested if: n=126 accepted, n=127 refused, on every surface" {
    for (SURFACES) |sf| {
        try expectAccept(sf, .nested_if, 126);
        try expectRefuse(sf, .nested_if, 127);
    }
}

test "F-213 unary minus: n=63 accepted, n=64 refused, on every surface" {
    for (SURFACES) |sf| {
        try expectAccept(sf, .neg, 63);
        try expectRefuse(sf, .neg, 64);
    }
}

test "F-213 chain: k=127 accepted, k=128 refused, on every surface" {
    for (SURFACES) |sf| {
        try expectAccept(sf, .chain, 127);
        try expectRefuse(sf, .chain, 128);
    }
}

test "F-213 deep shapes (n=20000) are refused without a crash, on every surface" {
    for (SURFACES) |sf| {
        try expectDeepRefused(sf, .parens, 20000);
        try expectDeepRefused(sf, .neg, 20000);
        try expectDeepRefused(sf, .chain, 20000);
        try expectDeepRefused(sf, .nested_if, if (sf.python_indent) 2500 else 20000);
    }
}
