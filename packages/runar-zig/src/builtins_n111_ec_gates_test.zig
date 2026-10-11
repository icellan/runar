//! N-111 -- the native Zig EC builtins must apply the compiled script's
//! operand gates: ecAdd / ecNegate: 64 bytes and x, y < p (R-117), off-curve
//! operands and O accepted; ecMul: on-curve or the all-zero identity O
//! (R-157); ecEncodeCompressed: width only. Rows come from the shared
//! on-chain file fixtures/n111-ec-operand-gates-onchain.json, every row
//! executed on @bsv/sdk Spend.validate by
//! packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts.
//!
//! An accepted row runs the plain builtin a contract body calls (a panic there
//! would kill this test run, so it is red too); an abort row runs the
//! `*Checked` variant, since a panic cannot be caught in-process, and must
//! return an error -- never a value. The plain builtin is that variant plus
//! `catch @panic`.
//!
//! Proves: for every ecAdd / ecMul / ecMulGen / ecNegate / ecEncodeCompressed
//! row, the on-chain value or an abort error.
//! Does NOT prove: the ecPointX / ecPointY rows -- the Zig native `Bigint` is
//! i64, so those accessors cannot return a 256-bit coordinate at all (a
//! return-type limitation, not an operand gate; their width check is an
//! untestable in-process panic); inputs outside the file; the script itself.

const std = @import("std");
const builtins = @import("builtins.zig");

const vectors_json = @embedFile("fixtures/n111-ec-operand-gates-onchain.json");

fn hexAlloc(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn runPlain(name: []const u8, p: []const u8, q: []const u8, k: i64) ?[]const u8 {
    if (std.mem.eql(u8, name, "ecAdd")) return builtins.ecAdd(p, q);
    if (std.mem.eql(u8, name, "ecMul")) return builtins.ecMul(p, k);
    if (std.mem.eql(u8, name, "ecMulGen")) return builtins.ecMulGen(k);
    if (std.mem.eql(u8, name, "ecNegate")) return builtins.ecNegate(p);
    if (std.mem.eql(u8, name, "ecEncodeCompressed")) return builtins.ecEncodeCompressed(p);
    return null;
}

fn runChecked(name: []const u8, p: []const u8, q: []const u8, k: i64) builtins.EcBuiltinError![]const u8 {
    if (std.mem.eql(u8, name, "ecAdd")) return builtins.ecAddChecked(p, q);
    if (std.mem.eql(u8, name, "ecMul")) return builtins.ecMulChecked(p, k);
    if (std.mem.eql(u8, name, "ecNegate")) return builtins.ecNegateChecked(p);
    if (std.mem.eql(u8, name, "ecEncodeCompressed")) return builtins.ecEncodeCompressedChecked(p);
    unreachable;
}

test "N-111: native EC builtins match the on-chain operand gates for every shared vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var checked: usize = 0;
    var mismatches: usize = 0;
    for (cases) |c| {
        const obj = c.object;
        const name = obj.get("fn").?.string;
        if (std.mem.eql(u8, name, "ecPointX") or std.mem.eql(u8, name, "ecPointY")) continue;
        const want = obj.get("expect").?.string;
        const p = if (obj.get("p")) |v| try hexAlloc(allocator, v.string) else try allocator.alloc(u8, 0);
        defer allocator.free(p);
        const q = if (obj.get("q")) |v| try hexAlloc(allocator, v.string) else try allocator.alloc(u8, 0);
        defer allocator.free(q);
        const k: i64 = if (obj.get("k")) |v| try std.fmt.parseInt(i64, v.string, 10) else 0;
        checked += 1;

        // N-184: ecOnCurve is a boolean predicate, not a hex-encoded value --
        // compare it directly rather than through hexAlloc/runPlain, whose
        // want_bytes path assumes a hex-string `expect`.
        if (std.mem.eql(u8, name, "ecOnCurve")) {
            const want_bool = std.mem.eql(u8, want, "true");
            const got = builtins.ecOnCurve(p);
            if (got != want_bool) {
                mismatches += 1;
                std.debug.print("N-111 {s} [{s}]: got {}, want {s}\n", .{ name, obj.get("why").?.string, got, want });
            }
            continue;
        }

        if (std.mem.eql(u8, want, "abort")) {
            if (runChecked(name, p, q, k)) |got| {
                mismatches += 1;
                std.debug.print("N-111 {s} [{s}]: script aborts, Zig returned a value\n", .{ name, obj.get("why").?.string });
                builtins.freeIfOwned(got);
            } else |_| {}
            continue;
        }
        const want_bytes = try hexAlloc(allocator, want);
        defer allocator.free(want_bytes);
        const got = runPlain(name, p, q, k).?;
        defer builtins.freeIfOwned(got);
        if (!std.mem.eql(u8, got, want_bytes)) {
            mismatches += 1;
            std.debug.print("N-111 {s} [{s}]: got {x}, want {s}\n", .{ name, obj.get("why").?.string, got, want });
        }
    }
    try std.testing.expect(checked >= 50);
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
