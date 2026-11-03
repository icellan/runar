//! N-476 -- an input-limit (source nesting) diagnostic raised inside a `return`
//! statement is anchored at the `return` keyword on every surface, as the TS
//! reference anchors it (source-limits.ts: `bad.sourceLocation ?? method`).
//!
//! Before this item `ReturnStmt.source_loc` was set only by parse_ts.zig and
//! input_limits.zig `stmtLoc` returned null for a return, so the diagnostic fell
//! back to the enclosing method's header on all nine surfaces.
//!
//! What this proves: for a `return value + value + ... ` chain one term past
//! MAX_SOURCE_NESTING, on each of the nine surfaces, the Zig tier prints
//! `<file>:<line>:<col>` where line/col are those of the `return` keyword,
//! computed from the source text (never copied from the compiler's output).
//! What this does not prove: that the TS tier prints the same text for these
//! nine sources (checked by hand when the item was written, not in this test);
//! the location of a return that is an implicit tail expression (Move, Rust,
//! Ruby), which takes the expression statement's location; any other
//! diagnostic that is anchored at a return statement.

const std = @import("std");
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

const Surface = struct {
    ext: []const u8,
    head: []const u8,
    /// The text before / after the chain on the `return` line.
    pre: []const u8,
    post: []const u8,
};

// Same heads as f213_source_nesting_limit.zig; the chain sits in a `return`.
const SURFACES = [_]Surface{
    .{
        .ext = "ts",
        .head = "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
        .pre = "    return ",
        .post = ";",
    },
    .{
        .ext = "sol",
        .head = "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n",
        .pre = "        return ",
        .post = ";",
    },
    .{
        .ext = "move",
        .head = "module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n",
        .pre = "        return ",
        .post = ";",
    },
    .{
        .ext = "go",
        .head = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n",
        .pre = "\treturn ",
        .post = "",
    },
    .{
        .ext = "rs",
        .head = "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n",
        .pre = "        return ",
        .post = ";",
    },
    .{
        .ext = "py",
        .head = "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n",
        .pre = "        return ",
        .post = "",
    },
    .{
        .ext = "zig",
        .head = "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n",
        .pre = "        return ",
        .post = ";",
    },
    .{
        .ext = "rb",
        .head = "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
        .pre = "    return ",
        .post = "",
    },
    .{
        .ext = "java",
        .head = "package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n",
        .pre = "        return ",
        .post = ";",
    },
};

/// One term past the limit: `value + value + ...` (128 terms), as the F-213 chain.
const CHAIN_TERMS = 128;

fn parseErrors(a: std.mem.Allocator, ext: []const u8, src: []const u8, file: []const u8) []const []const u8 {
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

test "N-476: a nesting diagnostic inside a return is anchored at the return keyword, on every surface" {
    var failures: usize = 0;
    for (SURFACES) |sf| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var body: std.ArrayListUnmanaged(u8) = .empty;
        try body.appendSlice(a, sf.pre);
        for (0..CHAIN_TERMS) |i| {
            if (i > 0) try body.appendSlice(a, " + ");
            try body.appendSlice(a, "value");
        }
        try body.appendSlice(a, sf.post);
        const src = try std.mem.replaceOwned(u8, a, sf.head, "{BODY}", body.items);
        const file = try std.fmt.allocPrint(a, "P.runar.{s}", .{sf.ext});

        // Expected anchor, from the source text: the `return` keyword.
        const at = std.mem.indexOf(u8, src, body.items).?;
        const line_start = if (std.mem.lastIndexOfScalar(u8, src[0..at], '\n')) |nl| nl + 1 else 0;
        const line: usize = std.mem.count(u8, src[0..line_start], "\n") + 1;
        const col: usize = std.mem.indexOf(u8, src[line_start..], "return").?;
        const want = try std.fmt.allocPrint(a, "{s}:{d}:{d}: {s}", .{ file, line, col, input_limits.SOURCE_NESTING_MESSAGE });

        const errs = parseErrors(a, sf.ext, src, file);
        var found = false;
        for (errs) |e| {
            if (std.mem.eql(u8, e, want)) found = true;
        }
        if (!found) {
            failures += 1;
            std.debug.print("N-476 {s}: want `{s}`; got:\n", .{ sf.ext, want });
            for (errs) |e| std.debug.print("  {s}\n", .{e});
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
