//! F-011 (CL-BUG-196) — an unterminated string or byte-string literal is
//! refused, never scanned onward into the lines that follow it.
//!
//! Pre-fix, this tier's .runar.py tokenizer scanned `b"cafe` up to the next
//! matching quote, three lines down in a comment, so the guard
//! `assert_(y < 5)` became literal DATA and the emitted script had no guard
//! (@bsv/sdk Spend.validate accepted y = 100 against it; evidence in the
//! F-011 remediation log). Its other tokenizers ran to the next quote the same
//! way, its Ruby tokenizer ended an unterminated literal silently, and its
//! Java tokenizer did not recognise a char literal at all.
//!
//! The rule is the TS reference's (packages/runar-compiler/src/errors.ts,
//! UNTERMINATED_STRING_LITERAL): a quoted literal that reaches a line break or
//! end of file before its closing quote is refused with exactly
//! "unterminated string literal" at its opening quote; on .runar.rs, for
//! Python triple-quoted strings, for .runar.go backtick raw strings and for
//! .runar.ts template literals only end of file counts; a Java char literal is
//! refused with "char literals are unsupported in Rúnar Java contracts".
//! Diagnostics here are `file:line:col: message` strings.
//!
//! What this proves: every surface of this tier (all nine are hand-written)
//! refuses the conformance negatives N52-N64 with that exact text at the
//! opening quote's line; the closed-literal controls, Python docstrings, a
//! Rust string and a Go struct tag that span lines are not refused for it.
//! What it does NOT prove: anything about the other tiers (their suites and
//! conformance/negatives/rejection-parity.test.ts), or literal forms the
//! tokenizers never scanned (Rust raw strings, heredocs, Zig `\\` lines).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const MSG = "unterminated string literal";
const CHAR_MSG = "char literals are unsupported in Rúnar Java contracts";

const Fx = struct { file: []const u8, line: u32, open: []const u8, closed: []const u8, msg: []const u8 };

const FIXTURES = [_]Fx{
    .{ .file = "N52-py-bytes-unterminated-swallow.runar.py", .line = 22, .open = "b\"cafe\n", .closed = "b\"cafe\"\n", .msg = MSG },
    .{ .file = "N53-py-string-unterminated.runar.py", .line = 13, .open = "'cafe\n", .closed = "'cafe'\n", .msg = MSG },
    .{ .file = "N54-py-docstring-unterminated.runar.py", .line = 19, .open = "follows.\n", .closed = "follows.\"\"\"\n", .msg = MSG },
    .{ .file = "N55-sol-string-unterminated.runar.sol", .line = 13, .open = "\"cafe\n", .closed = "\"cafe\";\n", .msg = MSG },
    .{ .file = "N56-move-string-unterminated.runar.move", .line = 12, .open = "\"cafe\n", .closed = "\"cafe\";\n", .msg = MSG },
    .{ .file = "N57-zig-string-unterminated.runar.zig", .line = 12, .open = "\"cafe\n", .closed = "\"cafe\";\n", .msg = MSG },
    .{ .file = "N58-rs-string-unterminated.runar.rs", .line = 13, .open = "\"cafe;\n", .closed = "\"cafe\";\n", .msg = MSG },
    .{ .file = "N59-java-string-unterminated.runar.java", .line = 22, .open = "\"cafe\n", .closed = "\"cafe\");\n", .msg = MSG },
    .{ .file = "N60-java-char-literal.runar.java", .line = 21, .open = "", .closed = "", .msg = CHAR_MSG },
    .{ .file = "N61-rb-single-quote-unterminated.runar.rb", .line = 10, .open = "'cafe\n", .closed = "'cafe'\n", .msg = MSG },
    .{ .file = "N62-rb-double-quote-unterminated.runar.rb", .line = 9, .open = "\"cafe\n", .closed = "\"cafe\"\n", .msg = MSG },
    .{ .file = "N63-go-string-unterminated.runar.go", .line = 18, .open = "\"cafe\n", .closed = "\"cafe\"\n", .msg = MSG },
    .{ .file = "N64-ts-string-unterminated.runar.ts", .line = 14, .open = "\"cafe;\n", .closed = "\"cafe\";\n", .msg = MSG },
};

/// True when `e` is `<file>:<line>:<col>: <msg>`.
fn isAt(e: []const u8, file: []const u8, line: u32, msg: []const u8, buf: []u8) bool {
    const prefix = std.fmt.bufPrint(buf, "{s}:{d}:", .{ file, line }) catch return false;
    if (!std.mem.startsWith(u8, e, prefix) or !std.mem.endsWith(u8, e, msg)) return false;
    const head = e[0 .. e.len - msg.len];
    return std.mem.endsWith(u8, head, ": ");
}

fn expectAt(source: []const u8, file: []const u8, msg: []const u8, line: u32) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = compiler_api.parseSource(arena_state.allocator(), source, file);
    var buf: [512]u8 = undefined;
    for (r.errors) |e| {
        if (isAt(e, file, line, msg, &buf)) return;
    }
    std.debug.print("{s}: want \"{s}\" at line {d}; got:\n", .{ file, msg, line });
    for (r.errors) |e| std.debug.print("  {s}\n", .{e});
    return error.TestExpectedDiagnostic;
}

fn expectNone(source: []const u8, file: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = compiler_api.parseSource(arena_state.allocator(), source, file);
    for (r.errors) |e| {
        if (std.mem.endsWith(u8, e, ": " ++ MSG)) {
            std.debug.print("{s}: refused as unterminated but it is not: {s}\n", .{ file, e });
            return error.TestUnexpectedDiagnostic;
        }
    }
}

test "F-011 conformance negatives N52-N64 are refused at the opening quote" {
    const a = std.testing.allocator;
    for (FIXTURES) |f| {
        const path = try std.fmt.allocPrint(a, "../../conformance/negatives/{s}", .{f.file});
        defer a.free(path);
        const src = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, a, .limited(1024 * 1024));
        defer a.free(src);
        try expectAt(src, f.file, f.msg, f.line);
        if (f.open.len > 0) {
            const idx = std.mem.indexOf(u8, src, f.open) orelse return error.ControlDidNotApply;
            const ctl = try std.mem.concat(a, u8, &.{ src[0..idx], f.closed, src[idx + f.open.len ..] });
            defer a.free(ctl);
            try expectNone(ctl, f.file);
        }
    }
}

const PY_HEAD = "from runar import SmartContract, Bigint, ByteString, public, assert_\n\n\n" ++
    "class G(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n" ++
    "    @public\n    def unlock(self, y: Bigint):\n";

test "F-011 .runar.py literal shapes" {
    inline for (.{ "b\"ca", "b'ca", "\"ca", "'ca" }) |lit| {
        try expectAt(PY_HEAD ++ "        t: ByteString = " ++ lit ++ "\n        assert_(y < 5)\n", "G.runar.py", MSG, 10);
        try expectAt(PY_HEAD ++ "        assert_(y < 5)\n        t: ByteString = " ++ lit, "G.runar.py", MSG, 11);
    }
    try expectAt(PY_HEAD ++ "        t: ByteString = b\"ca\\\n        assert_(y < 5)\n", "G.runar.py", MSG, 10);
    try expectAt(PY_HEAD ++ "        assert_(y < 5)\n        x = \"\"\"note\n", "G.runar.py", MSG, 11);
    try expectNone(PY_HEAD ++ "        '''Method docstring\n        on two lines.'''\n        \"\"\"one line\"\"\"\n        assert_(y < 5)\n", "G.runar.py");
}

test "F-011 other surface shapes" {
    try expectAt("pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { 'ca", "G.runar.sol", MSG, 3);
    try expectAt("module G {\n    public fun f(y: Int) {\n        let t: ByteString = b\"ca\\\n", "G.runar.move", MSG, 3);
    try expectAt("const runar = @import(\"runar", "G.runar.zig", MSG, 1);
    try expectAt("class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"\n  }\n}\n", "G.runar.java", MSG, 2);
    try expectNone("class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"fe\"); }\n}\n", "G.runar.java");
    inline for (.{ "'c';", "'c", "'\\''" }) |lit| {
        try expectAt("class G extends SmartContract {\n  void f() { " ++ lit ++ "\n  }\n}\n", "G.runar.java", CHAR_MSG, 2);
    }
    try expectAt("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\n  end\nend\n", "G.runar.rb", MSG, 4);
    try expectNone("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\"fe\"\n  end\nend\n", "G.runar.rb");
    try expectAt("package contract\n\nfunc (c *G) F() {\n\tt := \"ca\\\n}\n", "G.runar.go", MSG, 4);
    try expectAt("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\"readonly\"\n}\n", "G.runar.go", MSG, 4);
    try expectNone("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\n\"readonly\"`\n}\n", "G.runar.go");
    try expectAt("import { SmartContract } from 'runar-lang\n", "G.runar.ts", MSG, 1);
    try expectAt("class G extends SmartContract {\n  f(): void { const t = \"ca\n  }\n}\n", "G.runar.ts", MSG, 2);
    try expectNone("class G extends SmartContract {\n  f(): void { const t = \"ca\\\nfe\";\n  }\n}\n", "G.runar.ts");
    const rs = "use runar::prelude::*;\n\n#[runar::contract]\npub struct G {\n}\n\nimpl G {\n    pub fn unlock(&self, y: Bigint) {\n";
    try expectAt(rs ++ "        let t: ByteString = \"ca\\\"\n        assert!(y < 5);\n    }\n}\n", "G.runar.rs", MSG, 9);
    try expectNone(rs ++ "        let t: ByteString = \"ca\nfe\";\n        assert!(y < 5);\n    }\n}\n", "G.runar.rs");
}
