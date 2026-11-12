//! Ports #170 (original design: brendan-elas, #167): the C=1 Any-S binding and
//! the `@bindingVariant` directive in the Zig tier. The two blobs are pinned
//! here as literals so a Zig-only drift fails this file; execution of the same
//! bytes through @bsv/sdk Spend lives in
//! packages/runar-testing/src/__tests__/binding-variant.test.ts.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json = @import("../ir/json.zig");
const required_fields = @import("../ir/required_fields.zig");

/// 422 bytes: s = lowS((z+1) mod n), C=1 key 038ff83d...
const LOWS_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";
/// 376 bytes: s = z+1, no mod-n, no low-S (nVersion > 1 only).
const ALL_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";

fn counter(comptime directive: []const u8) []const u8 {
    return "class C extends StatefulSmartContract {\n" ++
        "  count: bigint;\n" ++
        "  constructor(count: bigint) { super(count); this.count = count; }\n" ++
        "  " ++ directive ++ "\n" ++
        "  public bump() { this.count++; }\n" ++
        "}\n";
}

fn scriptOf(a: std.mem.Allocator, src: []const u8, file: []const u8) ![]const u8 {
    const r = try compiler_api.compileSourceWithOptions(a, src, file, true);
    if (r.artifact_json) |j| a.free(j);
    for (r.warnings) |w| a.free(w);
    a.free(r.warnings);
    return r.script_hex;
}

/// Run the pipeline and return every error line joined, or null on success.
fn errorsOf(a: std.mem.Allocator, src: []const u8, file: []const u8) !?[]const u8 {
    var diag: compiler_api.Diagnostics = .{};
    _ = compiler_api.runPipeline(a, src, file, .{ .disable_constant_folding = true }, &diag) catch {
        return try std.mem.join(a, "\n", diag.errors.items);
    };
    return null;
}

test "bindingVariant: pinned sizes" {
    try std.testing.expectEqual(@as(usize, 422), LOWS_HEX.len / 2);
    try std.testing.expectEqual(@as(usize, 376), ALL_HEX.len / 2);
}

test "bindingVariant: default and explicit lowS emit the C=1 blob" {
    const a = std.testing.allocator;
    inline for (.{ "", "/** @bindingVariant lowS */" }) |d| {
        const s = try scriptOf(a, counter(d), "C.runar.ts");
        defer a.free(s);
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, s, LOWS_HEX));
        try std.testing.expect(std.mem.indexOf(u8, s, "02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0") == null);
    }
}

test "bindingVariant: all emits the compact blob" {
    const a = std.testing.allocator;
    const s = try scriptOf(a, counter("/** @bindingVariant all */"), "C.runar.ts");
    defer a.free(s);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, s, ALL_HEX));
    try std.testing.expect(std.mem.indexOf(u8, s, LOWS_HEX) == null);
}

test "bindingVariant: a nested if arm inherits the method variant" {
    const a = std.testing.allocator;
    const src = "class G extends SmartContract {\n  constructor() { super(); }\n  /** @bindingVariant all */\n" ++
        "  public unlock(a: SigHashPreimage, b: SigHashPreimage, c: boolean) {\n" ++
        "    if (c) { assert(checkPreimage(a)); } else { assert(checkPreimage(b)); }\n  }\n}\n";
    const s = try scriptOf(a, src, "G.runar.ts");
    defer a.free(s);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, s, ALL_HEX));
    try std.testing.expect(std.mem.indexOf(u8, s, LOWS_HEX) == null);
}

test "bindingVariant: directive errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = .{
        .{ "/** @bindingVariant: all */", "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`" },
        .{ "/** @bindingVariant high */", "@bindingVariant: unknown variant \"high\" (valid: lowS, all)" },
        .{ "/** @bindingVariant all */\n  // @bindingVariant lowS", "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one" },
    };
    inline for (cases) |c| {
        const e = (try errorsOf(a, counter(c[0]), "C.runar.ts")) orelse return error.TestUnexpectedSuccess;
        if (std.mem.indexOf(u8, e, c[1]) == null) {
            std.debug.print("got: {s}\n", .{e});
            return error.TestExpectedEqual;
        }
    }
    const priv = comptime "class C extends StatefulSmartContract {\n  count: bigint;\n  constructor(count: bigint) { super(count); this.count = count; }\n  /** @bindingVariant all */\n  private bump() { this.count++; }\n  public go() { this.bump(); }\n}\n";
    const e = (try errorsOf(a, priv, "C.runar.ts")) orelse return error.TestUnexpectedSuccess;
    try std.testing.expect(std.mem.indexOf(u8, e, "@bindingVariant directive on non-public method 'bump' has no effect") != null);
}

test "bindingVariant: the eight non-TS surfaces refuse the marker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const surfaces = .{
        .{ "C.runar.sol", "Solidity" }, .{ "C.runar.move", "Move" }, .{ "C.runar.py", "Python" }, .{ "C.runar.go", "Go DSL" },
        .{ "C.runar.rs", "Rust" },      .{ "C.runar.rb", "Ruby" },   .{ "C.runar.zig", "Zig" },   .{ "C.runar.java", "Java" },
    };
    inline for (surfaces) |s| {
        const want = "@bindingVariant directive is not supported by the " ++ s[1] ++ " surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured";
        const e = (try errorsOf(a, "// @bindingVariant all\n", s[0])) orelse return error.TestUnexpectedSuccess;
        try std.testing.expect(std.mem.indexOf(u8, e, want) != null);
    }
}

test "bindingVariant: --ir round trip carries all; the loader refuses an unknown variant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diag: compiler_api.Diagnostics = .{};
    const p = try compiler_api.runPipeline(a, counter("/** @bindingVariant all */"), "C.runar.ts", .{ .disable_constant_folding = true }, &diag);
    const ir = try json.serializeCanonicalJSON(a, p.program.?);
    try std.testing.expect(std.mem.indexOf(u8, ir, "\"bindingVariant\": \"all\"") != null);
    const back = try json.parseANFProgram(a, ir);
    var found = false;
    for (back.methods) |m| for (m.body) |b| switch (b.value) {
        .check_preimage => |cp| found = found or cp.binding_variant_all,
        else => {},
    };
    try std.testing.expect(found);
    const bad = try std.mem.replaceOwned(u8, a, ir, "\"bindingVariant\": \"all\"", "\"bindingVariant\": \"high\"");
    if (json.parseANFProgram(a, bad)) |_| return error.TestUnexpectedSuccess else |_| {}
    const got = required_fields.lastDiagnostic() orelse "";
    try std.testing.expect(std.mem.indexOf(u8, got, "bindingVariant must be \"lowS\" or \"all\"") != null);
}
