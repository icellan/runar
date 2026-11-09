//! N-509: a local cannot be re-declared in the same scope (spec/grammar.md).
//! One scope = one statement list; a method's parameters belong to its body's
//! top-level list. Shadowing in a NESTED list is not a re-declaration.
//! Mirrors packages/runar-compiler/src/__tests__/02-validate.test.ts (N-509).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const types = @import("../ir/types.zig");

const DEFAULT_CTOR = "super(k);\n    this.k = k;";

fn source(a: std.mem.Allocator, body: []const u8, ctor: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        a,
        "\nclass R extends SmartContract {{\n  readonly k: bigint;\n  constructor(k: bigint) {{\n    {s}\n  }}\n  public unlock(p: bigint, c: boolean) {{\n    {s}\n  }}\n}}\n",
        .{ ctor, body },
    );
}

fn msg(a: std.mem.Allocator, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "'{s}' is already declared in this scope and cannot be re-declared", .{name});
}

fn errors(a: std.mem.Allocator, src: []const u8) ![]types.CompilerDiagnostic {
    const parsed = parse_ts.parseTs(a, src, "R.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.ParseFailed;
    return (try validate.validate(a, contract)).errors;
}

const Refused = struct { body: []const u8, name: []const u8, ctor: []const u8 = DEFAULT_CTOR };

test "N-509 refuses a same-scope re-declaration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]Refused{
        .{ .body = "const a = 1n; const a = 2n; assert(a == p);", .name = "a" },
        .{ .body = "let x = 1n; let x = 2n; assert(x == p);", .name = "x" },
        .{ .body = "const a = 1n; let a = 2n; a = 3n; assert(a == p);", .name = "a" },
        .{ .body = "if (c) { let y = 1n; let y = 2n; assert(y == p); } assert(c);", .name = "y" },
        .{ .body = "if (c) { assert(c); } else { let y = 1n; let y = 2n; assert(y == p); }", .name = "y" },
        .{ .body = "let s = 0n; for (let i = 0n; i < 2n; i++) { let t = i; let t = i; s = s + t; } assert(s == p);", .name = "t" },
        .{ .body = "let p = 5n; assert(p == this.k && c);", .name = "p" },
        .{ .body = "assert(p == this.k && c);", .name = "k", .ctor = "super(k);\n    this.k = k;\n    const k = 2n;\n    assert(k > 0n);" },
    };
    for (cases) |tc| {
        const want = try msg(a, tc.name);
        var n: usize = 0;
        for (try errors(a, try source(a, tc.body, tc.ctor))) |d| {
            if (std.mem.eql(u8, d.message, want)) n += 1;
        }
        if (n != 1) {
            std.debug.print("want exactly one \"{s}\" for: {s}\n", .{ want, tc.body });
            return error.TestExpectedEqual;
        }
    }
}

test "N-509 reports the second declaration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try msg(a, "a");
    for (try errors(a, try source(a, "const a = 1n;\n    const a = 2n;\n    assert(a == p);", DEFAULT_CTOR))) |d| {
        if (std.mem.eql(u8, d.message, want)) {
            try std.testing.expectEqual(@as(u32, 10), d.location.?.line);
            return;
        }
    }
    return error.NoRedeclarationError;
}

test "N-509 accepts shadowing in a nested block, siblings and properties" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_][]const u8{
        "let x = 1n; if (c) { let x = 2n; assert(x == 2n); } assert(x == p);",
        "if (c) { let p = 5n; assert(p == 5n); } assert(p == this.k);",
        "const k = 5n; assert(k == p + this.k && c);",
        "let s = 0n; for (let i = 0n; i < 2n; i++) { let i = 7n; s = s + i; } assert(s == p && c);",
        "if (c) { let y = 1n; assert(y == p); } else { let y = 2n; assert(y == p); }",
        "if (c) { let y = 1n; assert(y == p); } let y = 2n; assert(y == p);",
        "let s = 0n; for (let i = 0n; i < 2n; i++) { s = s + i; } for (let i = 0n; i < 3n; i++) { s = s + i; } assert(s == p && c);",
    };
    for (cases) |body| {
        for (try errors(a, try source(a, body, DEFAULT_CTOR))) |d| {
            if (std.mem.indexOf(u8, d.message, "already declared") != null) {
                std.debug.print("unexpected \"{s}\" for: {s}\n", .{ d.message, body });
                return error.TestUnexpectedError;
            }
        }
    }
}
