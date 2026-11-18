//! Grok v1 frontend findings, Zig tier. The corpora are the cross-tier ones in
//! conformance/negatives/ (read relative to compilers/zig, the test cwd),
//! shared with the other six tiers' unit tests and the conformance gates.
//!
//! - GK-BUG-015: a repeated method name is a validate error with the shared
//!   message.
//! - GK-GAP-013: `lowerToANF` refuses malformed intent-intrinsic calls with a
//!   named LowerError instead of lowering them to `load_const ""`; typecheck
//!   still refuses first.
//! - GK-GAP-010: a public method's SigHashPreimage parameter must reach
//!   checkPreimage on every path.
//! - GK-GAP-005/006: suffixes match ignoring ASCII case (same hex), an unknown
//!   suffix is refused with the shared message, an empty name is TypeScript.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");

fn corpus(a: std.mem.Allocator, name: []const u8) !std.json.Value {
    const path = try std.fmt.allocPrint(a, "../../conformance/negatives/{s}", .{name});
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, a, .limited(4 * 1024 * 1024));
    return (try std.json.parseFromSlice(std.json.Value, a, raw, .{})).value;
}

fn str(v: std.json.Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}

/// validate errors, or (when validate is clean) typecheck errors.
fn frontendErrors(a: std.mem.Allocator, src: []const u8, file: []const u8) ![]const []const u8 {
    const parsed = compiler_api.parseSource(a, src, file);
    if (parsed.errors.len != 0) return parsed.errors;
    const contract = parsed.contract.?;
    const val = try compiler_api.validateForFile(a, contract, file);
    if (val.errors.len != 0) {
        var out: std.ArrayListUnmanaged([]const u8) = .empty;
        for (val.errors) |e| try out.append(a, e.message);
        return out.items;
    }
    return (try typecheck.typeCheck(a, contract)).errors;
}

fn contains(list: []const []const u8, want: []const u8) bool {
    for (list) |s| if (std.mem.indexOf(u8, s, want) != null) return true;
    return false;
}

test "GK-BUG-015: a repeated method name is a validate error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "duplicate-method-cases.json");
    for (c.object.get("cases").?.array.items) |case| {
        const errs = try frontendErrors(a, str(case, "src"), str(case, "file"));
        if (!contains(errs, str(case, "error"))) {
            std.debug.print("{s}: want {s}\n", .{ str(case, "name"), str(case, "error") });
            return error.TestExpectedRefusal;
        }
        const twin = try frontendErrors(a, str(case, "twin"), str(case, "file"));
        try std.testing.expectEqual(@as(usize, 0), twin.len);
    }
}

test "GK-GAP-013: lowerToANF refuses malformed intent intrinsics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = std.StaticStringMap(anyerror).initComptime(.{
        .{ "prev-arity", anf_lower.LowerError.ExtractPrevOutputScriptArity },
        .{ "prev-nonliteral-index", anf_lower.LowerError.ExtractPrevOutputScriptIndexNotLiteral },
        .{ "prev-nonliteral-prefixlen", anf_lower.LowerError.ExtractPrevOutputScriptPrefixLenNotLiteral },
        .{ "p2pkh-arity", anf_lower.LowerError.RequireOutputP2PKHArity },
        .{ "p2pkh-nonliteral-index", anf_lower.LowerError.RequireOutputP2PKHIndexNotLiteral },
    });
    const c = try corpus(a, "intent-shape-cases.json");
    for (c.object.get("cases").?.array.items) |case| {
        const parsed = compiler_api.parseSource(a, str(case, "src"), "Bad.runar.ts");
        try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
        const tc = try typecheck.typeCheck(a, parsed.contract.?);
        try std.testing.expect(tc.errors.len > 0);
        const expected = want.get(str(case, "name")).?;
        if (anf_lower.lowerToANF(a, parsed.contract.?)) |_| {
            std.debug.print("{s}: lowered instead of refusing\n", .{str(case, "name")});
            return error.TestExpectedRefusal;
        } else |err| {
            try std.testing.expectEqual(expected, @as(anyerror, err));
        }
    }
}

test "GK-GAP-010: SigHashPreimage parameter checked on every path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "preimage-checked-cases.json");
    for (c.object.get("refuse").?.array.items) |case| {
        const errs = try frontendErrors(a, str(case, "src"), str(case, "file"));
        if (!contains(errs, str(case, "error"))) {
            std.debug.print("{s}: not refused\n", .{str(case, "name")});
            return error.TestExpectedRefusal;
        }
    }
    for (c.object.get("accept").?.array.items) |case| {
        const errs = try frontendErrors(a, str(case, "src"), str(case, "file"));
        if (errs.len != 0) {
            std.debug.print("{s}: refused: {s}\n", .{ str(case, "name"), errs[0] });
            return error.TestUnexpectedRefusal;
        }
    }
}

test "GK-GAP-005/006: extension dispatch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const ts = try std.Io.Dir.cwd().readFileAlloc(io, "../../examples/ts/p2pkh/P2PKH.runar.ts", a, .limited(1 << 20));
    const py = try std.Io.Dir.cwd().readFileAlloc(io, "../../examples/python/p2pkh/P2PKH.runar.py", a, .limited(1 << 20));
    const pairs = [_][3][]const u8{
        .{ ts, "P2PKH.runar.ts", "P2PKH.RUNAR.TS" },
        .{ py, "P2PKH.runar.py", "P2PKH.RUNAR.PY" },
    };
    for (pairs) |p| {
        const lo = try compiler_api.compileSourceToHex(std.testing.allocator, p[0], p[1]);
        defer std.testing.allocator.free(lo);
        const up = try compiler_api.compileSourceToHex(std.testing.allocator, p[0], p[2]);
        defer std.testing.allocator.free(up);
        try std.testing.expectEqualStrings(lo, up);
    }
    const x = compiler_api.parseSource(a, ts, "P2PKH.runar.xyz");
    try std.testing.expect(x.contract == null);
    try std.testing.expectEqual(@as(usize, 1), x.errors.len);
    try std.testing.expectEqualStrings(
        "unsupported file extension: P2PKH.runar.xyz (expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java)",
        x.errors[0],
    );
    const n = compiler_api.parseSource(a, ts, "");
    try std.testing.expectEqual(@as(usize, 0), n.errors.len);
    try std.testing.expect(n.contract != null);
}

test "D10: a stateless Rust-DSL contract cannot declare tx_preimage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try corpus(a, "rust-tx-preimage-cases.json");
    try std.testing.expect(c.object.get("refuse").?.array.items.len >= 5);
    for (c.object.get("refuse").?.array.items) |case| {
        const parsed = compiler_api.parseSource(a, str(case, "src"), str(case, "file"));
        if (!contains(parsed.errors, str(case, "error"))) {
            std.debug.print("{s}: parser did not refuse ({d} errors)\n", .{ str(case, "name"), parsed.errors.len });
            return error.TestExpectedRefusal;
        }
    }
    for (c.object.get("accept").?.array.items) |case| {
        const parsed = compiler_api.parseSource(a, str(case, "src"), str(case, "file"));
        if (parsed.errors.len != 0) {
            std.debug.print("{s}: refused: {s}\n", .{ str(case, "name"), parsed.errors[0] });
            return error.TestUnexpectedRefusal;
        }
        const contract = parsed.contract.?;
        try std.testing.expectEqual(@import("../ir/types.zig").ParentClass.stateful_smart_contract, contract.parent_class);
        for (contract.properties) |p| try std.testing.expect(!std.mem.eql(u8, p.name, "txPreimage"));
        const errs = try frontendErrors(a, str(case, "src"), str(case, "file"));
        if (errs.len != 0) {
            std.debug.print("{s}: refused: {s}\n", .{ str(case, "name"), errs[0] });
            return error.TestUnexpectedRefusal;
        }
        const hex = try compiler_api.compileSourceToHex(std.testing.allocator, str(case, "src"), str(case, "file"));
        defer std.testing.allocator.free(hex);
        try std.testing.expect(hex.len > 0);
    }
}
