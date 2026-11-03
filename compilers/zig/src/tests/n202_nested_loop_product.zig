//! N-202: the source path bounds the PRODUCT of nested loop counts, not just
//! each loop's own count.
//!
//! `lowerForStatement` caps one for-loop at MAX_LOOP_COUNT (10,000). Two loops
//! of 9,000, one inside the other, each passed that cap while the unrolled work
//! was 81,000,000 iterations. F-283 refuses the same nest on the --ir path, so a
//! source contract compiled while its own emitted IR was refused on replay.
//!
//! Proves: on the Zig source path a 101 x 100 nest is refused with the shared
//! product diagnostic, also when the inner loop sits in an if arm, and a nest of
//! exactly 10,000 still compiles.
//! Does not prove: the other tiers (conformance/negatives/n202-nested-loop-
//! product-parity.test.ts, which also drives the 9000 x 9000 nest through this
//! tier's CLI behind a timeout), or loops reached through a private method call
//! that stack lowering inlines later -- the bound is per-method nesting in ANF,
//! the same rule the --ir loader applies.
//!
//! No watchdog: at 101 x 100 a regression is an acceptance (about 10,000
//! unrolled iterations, well under a second), never a hang.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

const PRODUCT_DIAG = "For loop unrolls to 100 iterations nested inside an enclosing loop of total count 101, producing 10100 total iterations, exceeding the maximum loop count of 10000.";

fn nestedLoopSource(alloc: std.mem.Allocator, outer: u32, inner: u32, in_if_arm: bool) ![]const u8 {
    const inner_loop = try std.fmt.allocPrint(alloc, "for (let j = 0n; j < {d}n; j++) {{ acc = acc + x; }}", .{inner});
    const body = if (in_if_arm)
        try std.fmt.allocPrint(alloc, "if (x > 0n) {{ {s} }}", .{inner_loop})
    else
        inner_loop;
    return std.fmt.allocPrint(alloc,
        \\import {{ SmartContract, assert }} from 'runar-lang';
        \\
        \\export class NestedLoops extends SmartContract {{
        \\  constructor() {{ super(); }}
        \\
        \\  public unlock(x: bigint): void {{
        \\    let acc: bigint = 0n;
        \\    for (let i = 0n; i < {d}n; i++) {{ {s} }}
        \\    assert(acc > x);
        \\  }}
        \\}}
        \\
    , .{ outer, body });
}

fn frontend(alloc: std.mem.Allocator, source: []const u8) !types.ContractNode {
    const parsed = parse_ts.parseTs(alloc, source, "NestedLoops.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;

    const val_result = try validate.validate(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    return tc_result.contract;
}

test "N-202: a nested loop whose product passes MAX_LOOP_COUNT is refused" {
    for ([_]bool{ false, true }) |in_if_arm| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const contract = try frontend(alloc, try nestedLoopSource(alloc, 101, 100, in_if_arm));

        var diag: anf_lower.LowerDiagnostic = .{};
        const result = anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);
        try std.testing.expectError(anf_lower.LowerError.LoopCountTooLarge, result);

        const message = diag.message orelse return error.TestExpectedDiagnostic;
        try std.testing.expect(std.mem.indexOf(u8, message, PRODUCT_DIAG) != null);
    }
}

test "N-202: a nested loop of exactly MAX_LOOP_COUNT still compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const result = try compiler_api.compileSourceWithOptions(
        alloc,
        try nestedLoopSource(alloc, 100, 100, false),
        "NestedLoops.runar.ts",
        false,
    );
    try std.testing.expect(result.script_hex.len > 0);
}
