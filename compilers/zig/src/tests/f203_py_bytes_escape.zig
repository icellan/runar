//! F-203 (CL-BUG-208..213) — .runar.py byte literals decode escapes the way
//! CPython bytes literals do.
//!
//! Pre-fix this tier hex-encoded every character of `b'\n'`, `b'\0'`,
//! `b'\\'` one by one (5c 6e, 5c 30, 5c 5c), so the script compared against
//! different bytes than CPython (what pytest runs) and than other tiers.
//!
//! The rule is the TS reference's (packages/runar-compiler/src/passes/
//! 01-parse-python.ts, decodePyLiteral): b'..' decodes `\\ \' \" \a \b \f \n
//! \r \t \v`, octal `\NNN` (1-3 digits, at most 0o377) and `\xHH` (exactly two
//! hex digits); any other escape is refused with
//! "invalid escape sequence '<escape>'", a non-ASCII byte in b'..' with
//! "bytes can only contain ASCII literal characters"; plain '..' strings
//! decode the same escapes and refuse `\u` / `\U` / `\N`.
//! Every expected byte string below is CPython's own
//! (`python3 -c "print(b'..'.hex())"`).
//!
//! What this proves: this tier compiles each escape to CPython's bytes and
//! refuses each undefined form with the shared diagnostic.
//! What it does NOT prove: the other tiers (their suites and
//! conformance/negatives/py-bytes-escape-parity.test.ts), or triple-quoted
//! docstrings, which are skipped, never compiled.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const FILE = "Esc.runar.py";

fn contract(allocator: std.mem.Allocator, lit: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\from runar import SmartContract, ByteString, public, assert_
        \\
        \\
        \\class Esc(SmartContract):
        \\    def __init__(self):
        \\        super().__init__()
        \\
        \\    @public
        \\    def unlock(self, x: ByteString):
        \\        assert_(x == {s})
        \\
    , .{lit});
}

/// Minimal push of `hex` as the emitter encodes byte strings, then OP_EQUAL.
fn guardHex(allocator: std.mem.Allocator, hex: []const u8) ![]const u8 {
    const n = hex.len / 2;
    if (n == 1) {
        const b = try std.fmt.parseInt(u8, hex, 16);
        if (b >= 1 and b <= 16) return std.fmt.allocPrint(allocator, "{x:0>2}87", .{0x50 + @as(u16, b)});
        if (b == 0x81) return "4f87";
    }
    return std.fmt.allocPrint(allocator, "{x:0>2}{s}87", .{ n, hex });
}

const Case = struct { body: []const u8, hex: []const u8 };

const CASES = [_]Case{
    .{ .body = "b'\\0'", .hex = "00" },
    .{ .body = "b'\\00'", .hex = "00" },
    .{ .body = "b'\\000'", .hex = "00" },
    .{ .body = "b'\\7'", .hex = "07" },
    .{ .body = "b'\\101'", .hex = "41" },
    .{ .body = "b'\\377'", .hex = "ff" },
    .{ .body = "b'\\1234'", .hex = "5334" },
    .{ .body = "b'a\\0b'", .hex = "610062" },
    .{ .body = "b'\\08'", .hex = "0038" },
    .{ .body = "b'\\n'", .hex = "0a" },
    .{ .body = "b'\\t'", .hex = "09" },
    .{ .body = "b'\\r'", .hex = "0d" },
    .{ .body = "b'\\\\'", .hex = "5c" },
    .{ .body = "b'\\''", .hex = "27" },
    .{ .body = "b'\\\"'", .hex = "22" },
    .{ .body = "b\"\\'\\\"\"", .hex = "2722" },
    .{ .body = "b'\\a'", .hex = "07" },
    .{ .body = "b'\\b'", .hex = "08" },
    .{ .body = "b'\\f'", .hex = "0c" },
    .{ .body = "b'\\v'", .hex = "0b" },
    .{ .body = "b'\\xde\\xAD'", .hex = "dead" },
    .{ .body = "b'\\x00\\x6a'", .hex = "006a" },
    .{ .body = "b'ab'", .hex = "6162" },
    .{ .body = "b'\\\\n'", .hex = "5c6e" },
    .{ .body = "b'x\\ty\\nz'", .hex = "7809790a7a" },
    .{ .body = "\"\\x61\\x62\"", .hex = "ab" },
};

test "F-203 b'..' escapes compile to CPython's bytes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var failed = false;
    for (CASES) |c| {
        const want = try guardHex(a, c.hex);
        const got = compiler_api.compileSourceToHex(a, try contract(a, c.body), FILE) catch |e| {
            std.debug.print("{s}: compile failed: {s}\n", .{ c.body, @errorName(e) });
            failed = true;
            continue;
        };
        if (!std.mem.eql(u8, got, want)) {
            std.debug.print("{s}: want {s}, got {s}\n", .{ c.body, want, got });
            failed = true;
        }
    }
    try std.testing.expect(!failed);
}

const Refused = struct { lit: []const u8, msg: []const u8 };

const REFUSED = [_]Refused{
    .{ .lit = "b'\\q'", .msg = "invalid escape sequence '\\q'" },
    .{ .lit = "b'\\x4'", .msg = "invalid escape sequence '\\x'" },
    .{ .lit = "b'\\xg0'", .msg = "invalid escape sequence '\\x'" },
    .{ .lit = "b'\\400'", .msg = "invalid escape sequence '\\400'" },
    .{ .lit = "b'\\N{DIGIT ONE}'", .msg = "invalid escape sequence '\\N'" },
    .{ .lit = "b'\\u0041'", .msg = "invalid escape sequence '\\u'" },
    .{ .lit = "b'\\U00000041'", .msg = "invalid escape sequence '\\U'" },
    .{ .lit = "\"\\q\"", .msg = "invalid escape sequence '\\q'" },
    .{ .lit = "\"\\u0061\"", .msg = "invalid escape sequence '\\u'" },
    .{ .lit = "b'\xc3\xa9'", .msg = "bytes can only contain ASCII literal characters" },
};

test "F-203 undefined escapes are refused with the shared diagnostic" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var failed = false;
    for (REFUSED) |c| {
        const r = compiler_api.parseSource(a, try contract(a, c.lit), FILE);
        var found = false;
        for (r.errors) |e| {
            if (std.mem.endsWith(u8, e, c.msg)) found = true;
        }
        if (!found) {
            std.debug.print("{s}: want \"{s}\"; got:\n", .{ c.lit, c.msg });
            for (r.errors) |e| std.debug.print("  {s}\n", .{e});
            failed = true;
        }
    }
    try std.testing.expect(!failed);
}

test "F-203 prefix forms and a backslash-newline continuation stay refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for ([_][]const u8{ "rb'\\n'", "br'\\n'", "B'\\n'", "b'ab\\\ncd'" }) |lit| {
        const r = compiler_api.parseSource(a, try contract(a, lit), FILE);
        if (r.errors.len == 0) {
            std.debug.print("{s}: accepted\n", .{lit});
            return error.TestExpectedRefusal;
        }
    }
}
