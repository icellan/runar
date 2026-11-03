//! F-026 (CL-BUG-198) — an integer literal means what its host language says
//! it means, on every surface, or it is refused.
//!
//! Pre-fix, this tier's .runar.zig tokenizer scanned decimal digits only, so
//! `0b1010` lexed as `0` plus the identifier `b1010`. In a struct-field default
//! the stray identifier was skipped and the field initialised to 0
//! (`runar.assert(amount > self.target)` compiled to `OP_0 OP_GREATERTHAN`;
//! @bsv/sdk Spend.validate accepted amount = 5). Its .runar.py tokenizer had
//! the same hole, `012` read as 12 or 0 depending on the surface, and `0x` on
//! .runar.sol / .runar.move was a ByteString only when its digit count was even.
//!
//! The rule is the TS reference's (packages/runar-compiler/src/passes/
//! int-literal.ts, user decision R15): the number token runs over every glued
//! [0-9A-Za-z_] character and must be an integer literal of the surface's host
//! language, with that language's value (table:
//! conformance/negatives/int-literal-cases.json, generated from the host
//! toolchains); anything else is refused with
//! "invalid <Language> integer literal '<text>'". Also: .zig call and array
//! lists require commas; .py refuses a second statement on one line.
//!
//! What this proves: this tier's validator reproduces every table row; every
//! tokenizer (all nine surfaces are hand-written here) accepts exactly the
//! table's forms with its values and refuses the rest with the shared text;
//! the attempt-1 exploit shapes read 10; the absorbing paths are closed.
//! What it does NOT prove: the other tiers, or the Solidity / Move rows
//! themselves (documentation-derived).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const int_literal = @import("../passes/int_literal.zig");
const types = @import("../ir/types.zig");

const ZIG_COMMA = "expected ',' between list elements";
const PY_LINE_BREAK = "expected a line break between statements";
const SURFACES = [_][]const u8{ "ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java" };

fn template(a: std.mem.Allocator, surface: []const u8, l: []const u8) ![]const u8 {
    if (std.mem.eql(u8, surface, "ts")) return std.fmt.allocPrint(a, "import {{ SmartContract, assert }} from 'runar-lang';\n\nclass T extends SmartContract {{\n  readonly target: bigint;\n\n  constructor(target: bigint) {{\n    super(target);\n    this.target = target;\n  }}\n\n  public verify(a: bigint): void {{\n    assert(a > {s});\n  }}\n}}\n", .{l});
    if (std.mem.eql(u8, surface, "sol")) return std.fmt.allocPrint(a, "pragma runar ^0.1.0;\n\ncontract T is SmartContract {{\n    int immutable target;\n\n    constructor(int _target) {{\n        target = _target;\n    }}\n\n    function verify(int a) public {{\n        require(a > {s});\n    }}\n}}\n", .{l});
    if (std.mem.eql(u8, surface, "move")) return std.fmt.allocPrint(a, "module T {{\n    use runar::types::{{Int}};\n\n    struct T {{\n        target: Int,\n    }}\n\n    public fun verify(contract: &T, a: Int) {{\n        assert!(a > {s});\n    }}\n}}\n", .{l});
    if (std.mem.eql(u8, surface, "go")) return std.fmt.allocPrint(a, "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype T struct {{\n\trunar.SmartContract\n\tTarget runar.Int `runar:\"readonly\"`\n}}\n\nfunc (c *T) Verify(a runar.Int) {{\n\trunar.Assert(a > {s})\n}}\n", .{l});
    if (std.mem.eql(u8, surface, "rs")) return std.fmt.allocPrint(a, "use runar::prelude::*;\n\n#[runar::contract]\nstruct T {{\n    #[readonly]\n    target: Int,\n}}\n\nimpl T {{\n    pub fn verify(&self, a: Int) {{\n        assert!(a > {s});\n    }}\n}}\n", .{l});
    if (std.mem.eql(u8, surface, "py")) return std.fmt.allocPrint(a, "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > {s})\n", .{l});
    if (std.mem.eql(u8, surface, "zig")) return std.fmt.allocPrint(a, "const runar = @import(\"runar\");\n\npub const T = struct {{\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {{\n        return .{{ .target = target }};\n    }}\n\n    pub fn verify(self: *const T, a: i64) void {{\n        _ = self;\n        runar.assert(a > {s});\n    }}\n}};\n", .{l});
    if (std.mem.eql(u8, surface, "rb")) return std.fmt.allocPrint(a, "require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > {s}\n  end\nend\n", .{l});
    return std.fmt.allocPrint(a, "package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {{\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {{\n        super(target);\n        this.target = target;\n    }}\n\n    @Public\n    void verify(Bigint a) {{\n        assertThat(a.gt(Bigint.of({s})));\n    }}\n}}\n", .{l});
}

fn fileFor(a: std.mem.Allocator, surface: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "T.runar.{s}", .{surface});
}

fn collectExpr(a: std.mem.Allocator, e: types.Expression, out: *std.ArrayListUnmanaged([]const u8)) std.mem.Allocator.Error!void {
    switch (e) {
        .literal_int => |v| try out.append(a, try std.fmt.allocPrint(a, "{d}", .{v})),
        .literal_bigint => |s| try out.append(a, s),
        .binary_op => |b| {
            try collectExpr(a, b.left, out);
            try collectExpr(a, b.right, out);
        },
        .unary_op => |u| try collectExpr(a, u.operand, out),
        .call => |c| for (c.args) |x| try collectExpr(a, x, out),
        .method_call => |m| for (m.args) |x| try collectExpr(a, x, out),
        .ternary => |t| {
            try collectExpr(a, t.condition, out);
            try collectExpr(a, t.then_expr, out);
            try collectExpr(a, t.else_expr, out);
        },
        .array_literal => |xs| for (xs) |x| try collectExpr(a, x, out),
        else => {},
    }
}

fn collectStmts(a: std.mem.Allocator, stmts: []types.Statement, out: *std.ArrayListUnmanaged([]const u8)) !void {
    for (stmts) |s| switch (s) {
        .expr_stmt => |x| try collectExpr(a, x.expr, out),
        .assert_stmt => |x| try collectExpr(a, x.condition, out),
        .const_decl => |x| try collectExpr(a, x.value, out),
        .let_decl => |x| if (x.value) |v| try collectExpr(a, v, out),
        else => {},
    };
}

const Parsed = struct { vals: [][]const u8, errors: []const []const u8, contract: ?types.ContractNode };

fn literals(a: std.mem.Allocator, src: []const u8, file: []const u8) !Parsed {
    const r = compiler_api.parseSource(a, src, file);
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    if (r.contract) |c| {
        for (c.methods) |m| if (std.mem.eql(u8, m.name, "verify")) try collectStmts(a, m.body, &out);
    }
    return .{ .vals = out.items, .errors = r.errors, .contract = r.contract };
}

fn has(errs: []const []const u8, want: []const u8) bool {
    for (errs) |e| if (std.mem.indexOf(u8, e, want) != null) return true;
    return false;
}

fn loadCases(a: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const src = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "../../conformance/negatives/int-literal-cases.json", a, .limited(4 * 1024 * 1024));
    return std.json.parseFromSlice(std.json.Value, a, src, .{});
}

test "F-026 the validator reproduces the host-language table" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const doc = try loadCases(a);
    const cases = doc.value.object.get("cases").?.object;
    try std.testing.expectEqual(@as(usize, 9), cases.count());
    var bad: usize = 0;
    var it = cases.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.array.items) |row| {
            const lit = row.array.items[0].string;
            const want: ?[]const u8 = switch (row.array.items[1]) {
                .string => |s| s,
                else => null,
            };
            var got: ?[]const u8 = null;
            if (int_literal.parse(a, entry.key_ptr.*, lit)) |l| {
                if (!l.neg_only) got = if (l.small) |v| try std.fmt.allocPrint(a, "{d}", .{v}) else l.big.?;
            }
            const same = if (want) |w| (got != null and std.mem.eql(u8, got.?, w)) else got == null;
            if (!same) {
                bad += 1;
                std.debug.print("{s} {s}: want {?s}, got {?s}\n", .{ entry.key_ptr.*, lit, want, got });
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "F-026 every tokenizer applies the table" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const doc = try loadCases(a);
    const cases = doc.value.object.get("cases").?.object;
    var bad: usize = 0;
    for (SURFACES) |surf| {
        for (cases.get(surf).?.array.items) |row| {
            const lit = row.array.items[0].string;
            const p = try literals(a, try template(a, surf, lit), try fileFor(a, surf));
            switch (row.array.items[1]) {
                .string => |want| {
                    if (p.errors.len != 0 or p.vals.len != 1 or !std.mem.eql(u8, p.vals[0], want)) {
                        bad += 1;
                        std.debug.print("{s} {s}: want [{s}], got {d} values, errors:\n", .{ surf, lit, want, p.vals.len });
                        for (p.vals) |v| std.debug.print("  value {s}\n", .{v});
                        for (p.errors) |e| std.debug.print("  {s}\n", .{e});
                    }
                },
                else => {
                    if (!has(p.errors, int_literal.invalidIntegerLiteral(a, surf, lit))) {
                        bad += 1;
                        std.debug.print("{s} {s}: not refused with the shared text\n", .{ surf, lit });
                        for (p.errors) |e| std.debug.print("  {s}\n", .{e});
                    }
                },
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "F-026 unary-minus-only literals" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const accept = [_][3][]const u8{
        .{ "java", "-2147483648", "2147483648" },  .{ "java", "- 9223372036854775808L", "9223372036854775808" },
        .{ "rs", "-128i8", "128" },                 .{ "rs", "-(128i8)", "128" },
        .{ "rs", "-9223372036854775808i64", "9223372036854775808" },
    };
    for (accept) |c| {
        const p = try literals(a, try template(a, c[0], c[1]), try fileFor(a, c[0]));
        if (p.errors.len != 0 or p.vals.len != 1 or !std.mem.eql(u8, p.vals[0], c[2])) {
            std.debug.print("{s} {s}: {d} values\n", .{ c[0], c[1], p.vals.len });
            for (p.errors) |e| std.debug.print("  {s}\n", .{e});
            return error.TestUnexpectedResult;
        }
    }
    const refuse = [_][3][]const u8{
        .{ "java", "-(2147483648)", "2147483648" }, .{ "java", "1 - 2147483648", "2147483648" },
        .{ "java", "2147483648", "2147483648" },    .{ "java", "-9223372036854775808", "9223372036854775808" },
        .{ "rs", "128i8", "128i8" },                .{ "rs", "1 - 128i8", "128i8" },
        .{ "rs", "-129i8", "129i8" },
    };
    for (refuse) |c| {
        const p = try literals(a, try template(a, c[0], c[1]), try fileFor(a, c[0]));
        if (!has(p.errors, int_literal.invalidIntegerLiteral(a, c[0], c[2]))) {
            std.debug.print("{s} {s}: not refused\n", .{ c[0], c[1] });
            return error.TestUnexpectedResult;
        }
    }
}

fn zigSrc(a: std.mem.Allocator, params: []const u8, body: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "const runar = @import(\"runar\");\n\npub const T = struct {{\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {{\n        return .{{ .target = target }};\n    }}\n\n    pub fn verify(self: *const T, amount: i64{s}) void {{\n        _ = self;\n{s}\n    }}\n}};\n", .{ params, body });
}

fn pySrc(a: std.mem.Allocator, params: []const u8, body: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint{s}):\n{s}\n", .{ params, body });
}

fn expectOnlyTen(p: Parsed) !void {
    if (p.errors.len != 0 or p.vals.len != 1 or !std.mem.eql(u8, p.vals[0], "10")) {
        std.debug.print("want [10], got {d} values\n", .{p.vals.len});
        for (p.vals) |v| std.debug.print("  value {s}\n", .{v});
        for (p.errors) |e| std.debug.print("  {s}\n", .{e});
        return error.TestUnexpectedResult;
    }
}

test "F-026 attempt-1 exploit shapes read the literal" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try expectOnlyTen(try literals(a, try zigSrc(a, ", b1010: runar.ByteString", "        runar.assert(amount > 0b1010);"), "T.runar.zig"));
    const r = try literals(a, try zigSrc(a, ", B1010: i64", "        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);"), "T.runar.zig");
    try std.testing.expect(has(r.errors, int_literal.invalidIntegerLiteral(a, "zig", "0B1010")));
    inline for (.{ "0b1010", "0o12", "0xa" }) |lit| {
        const src = "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64 = " ++ lit ++ ",\n\n    pub fn verify(self: *const T, amount: i64) void {\n        runar.assert(amount > self.target);\n    }\n};\n";
        const p = compiler_api.parseSource(a, src, "T.runar.zig");
        try std.testing.expectEqual(@as(usize, 0), p.errors.len);
        try std.testing.expectEqual(@as(i64, 10), p.contract.?.properties[0].initializer.?.literal_int);
    }
    try expectOnlyTen(try literals(a, try pySrc(a, ", b1010: Bigint", "        lim = 0b1010\n        assert_(amount > lim)"), "T.runar.py"));
    inline for (.{ "0o12", "0b1010" }) |lit| {
        const src = "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n    limit: Bigint = " ++ lit ++ "\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n";
        const p = compiler_api.parseSource(a, src, "T.runar.py");
        try std.testing.expectEqual(@as(usize, 0), p.errors.len);
        try std.testing.expectEqual(@as(i64, 10), p.contract.?.properties[1].initializer.?.literal_int);
    }
    inline for (.{ "0b102", "0o19" }) |lit| {
        const p = try literals(a, try template(a, "ts", lit), "T.runar.ts");
        try std.testing.expect(has(p.errors, int_literal.invalidIntegerLiteral(a, "ts", lit)));
    }
}

test "F-026 absorbing paths" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expect(has((try literals(a, try zigSrc(a, ", b: i64", "        runar.assert(runar.within(amount b, 20));"), "T.runar.zig")).errors, ZIG_COMMA));
    try std.testing.expect(!has((try literals(a, try zigSrc(a, ", b: i64", "        runar.assert(runar.within(amount, b, 20,));"), "T.runar.zig")).errors, ZIG_COMMA));
    try std.testing.expect(has((try literals(a, try zigSrc(a, "", "        const xs = [_]i64{ 1 2, 3 };\n        runar.assert(amount > xs[0]);"), "T.runar.zig")).errors, ZIG_COMMA));
    try std.testing.expect(has((try literals(a, try zigSrc(a, "", "        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);"), "T.runar.zig")).errors, ZIG_COMMA));
    try std.testing.expect(has((try literals(a, try pySrc(a, ", b: Bigint", "        lim = 10 b\n        assert_(amount > lim)"), "T.runar.py")).errors, PY_LINE_BREAK));
    try std.testing.expect(has((try literals(a, try pySrc(a, "", "        assert_(amount > 1) assert_(amount > 2)"), "T.runar.py")).errors, PY_LINE_BREAK));
    const cls = "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n";
    try std.testing.expect(has(compiler_api.parseSource(a, cls, "T.runar.py").errors, PY_LINE_BREAK));
    const ts_src = try std.mem.replaceOwned(u8, a, try template(a, "ts", "10"), "assert(a > 10);", "assert(a > 10;");
    try std.testing.expect(compiler_api.parseSource(a, ts_src, "T.runar.ts").errors.len != 0);
}
