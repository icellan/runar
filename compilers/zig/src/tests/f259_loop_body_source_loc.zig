//! F-259 -- an unrolled loop body's opcodes map to the body statement's line,
//! not to the loop header's line.
//!
//! Before the fix `lowerForLoop` lowered every body binding without updating
//! `current_source_loc`, so every opcode of every unrolled iteration inherited
//! the enclosing loop binding's location (the `while` line). Mirrors
//! packages/runar-compiler/src/__tests__/f259-loop-body-source-loc.test.ts.
//!
//! Convention (same in all 7 tiers): each body binding's own location is used
//! while it lowers; a body binding without one keeps the loop's location. The
//! per-iteration iteration-variable push stays on the loop's line.
//!
//! What this proves: on the Zig surface of examples/zig/bounded-loop (copied
//! verbatim below), every body op of all five unrolled iterations maps to the
//! body line and column, and only the five iteration-variable pushes
//! (OP_0..OP_4) map to the loop line.
//!
//! What this does not prove: anything about the other tiers, nested loops, or
//! body bindings the ANF lowerer leaves without a location. It equates byte
//! index with opcodeIndex, which it checks holds (no push-data opcodes).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

// Verbatim copy of examples/zig/bounded-loop/BoundedLoop.runar.zig.
const SOURCE =
    \\const runar = @import("runar");
    \\
    \\pub const BoundedLoop = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    expectedSum: i64,
    \\
    \\    pub fn init(expectedSum: i64) BoundedLoop {
    \\        return .{ .expectedSum = expectedSum };
    \\    }
    \\
    \\    pub fn verify(self: *const BoundedLoop, start: i64) void {
    \\        var sum: i64 = 0;
    \\        var i: i64 = 0;
    \\        while (i < 5) : (i += 1) {
    \\            sum = sum + start + i;
    \\        }
    \\        runar.assert(sum == self.expectedSum);
    \\    }
    \\};
    \\
;

const Pos = struct { line: i64, column: i64 };

fn find(needle: []const u8, anchor: []const u8) !Pos {
    var it = std.mem.splitScalar(u8, SOURCE, '\n');
    var line: i64 = 1;
    while (it.next()) |l| : (line += 1) {
        if (std.mem.indexOf(u8, l, needle) != null) {
            const col = std.mem.indexOf(u8, l, anchor) orelse return error.AnchorMissing;
            return .{ .line = line, .column = @intCast(col) };
        }
    }
    return error.NeedleMissing;
}

test "F-259: loop-body ops map to the body line, iteration pushes to the loop line" {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSourceWithOptions(allocator, SOURCE, "BoundedLoop.runar.zig", true);
    defer result.deinit(allocator);

    const hex = result.script_hex;
    var b: usize = 0;
    while (b < hex.len) : (b += 2) {
        const op = try std.fmt.parseInt(u8, hex[b .. b + 2], 16);
        try std.testing.expect(op == 0 or op > 0x4e);
    }
    const iter_at = [_]usize{ 1, 9, 17, 25, 33 };
    const iter_op = [_]u8{ 0x00, 0x51, 0x52, 0x53, 0x54 };
    for (iter_at, iter_op) |at, want| {
        try std.testing.expectEqual(want, try std.fmt.parseInt(u8, hex[2 * at .. 2 * at + 2], 16));
    }

    const loop_pos = try find("while (i < 5)", "while");
    const body_pos = try find("sum = sum + start + i", "sum");

    const artifact = result.artifact_json orelse return error.MissingArtifact;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, artifact, .{});
    defer parsed.deinit();
    const mappings = parsed.value.object.get("sourceMap").?.object.get("mappings").?.array.items;

    var seen: usize = 0;
    for (mappings) |m| {
        const idx: usize = @intCast(m.object.get("opcodeIndex").?.integer);
        if (idx < 1 or idx > 39) continue;
        seen += 1;
        const is_push = std.mem.indexOfScalar(usize, &iter_at, idx) != null;
        const want = if (is_push) loop_pos else body_pos;
        const got = Pos{ .line = m.object.get("line").?.integer, .column = m.object.get("column").?.integer };
        if (got.line != want.line or got.column != want.column) {
            std.debug.print("opcode {d} mapped to {d}:{d}, want {d}:{d}\n", .{ idx, got.line, got.column, want.line, want.column });
            return error.WrongLoopOpLocation;
        }
    }
    try std.testing.expectEqual(@as(usize, 39), seen);
}
