//! Regression tests for CL-BUG-088 / R-009: nothing bounded the magnitude of an
//! unrolled loop's iteration count on the SOURCE path, in any tier.
//!
//! This tier narrows twice, and both narrowings were unguarded:
//!
//!   1. The surface parsers collapse a for-loop bound to a concrete `i64`. A
//!      literal outside `i64` becomes a `.literal_bigint` node instead, which
//!      leaves `bound_is_const = false` — so 2^63, 2^64+10 and 10^20 are all
//!      refused by pass 2, but with "For loop bound must be a compile-time
//!      constant", a diagnostic that describes a *runtime* bound and tells the
//!      author nothing about what actually went wrong.
//!   2. ANF lowering then does `const count: u32 = if (raw > 0) @intCast(raw)`.
//!      `@intCast` on an out-of-range value is illegal behaviour: a
//!      safety-checked PANIC in Debug/ReleaseSafe, undefined behaviour in
//!      ReleaseFast. A bound of 2^63 - 1 — a perfectly ordinary `i64` literal —
//!      reached it. So did `raw = base + 1` for an inclusive loop at the i64
//!      ceiling, which overflows before the cast even runs.
//!
//! And the ceiling half: `MAX_LOOP_COUNT` (10000) existed nowhere in this tier,
//! so a bound of 10001 unrolled without complaint.
//!
//! What these tests pin: an out-of-range or over-ceiling loop bound is a
//! compile-time refusal naming the loop and the limit, and a valid loop still
//! compiles to the exact bytes it produced before the guard existed.
//!
//! No watchdog is needed here (unlike the TypeScript / Python / Ruby tiers):
//! every magnitude below is refused before any unrolling starts, and the
//! pre-fix failure modes were a panic and a wrong-diagnostic rejection, not a
//! hang.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

/// Build a contract whose single public method unrolls a for loop with the
/// given literal bound. `{s}` is the bound's decimal text.
fn loopBoundSource(alloc: std.mem.Allocator, bound: []const u8) ![]const u8 {
    return std.fmt.allocPrint(alloc,
        \\import {{ SmartContract, assert }} from 'runar-lang';
        \\
        \\export class LoopBound extends SmartContract {{
        \\  constructor() {{ super(); }}
        \\
        \\  public unlock(x: bigint): void {{
        \\    let acc: bigint = 0n;
        \\    for (let i = 0n; i < {s}n; i++) {{
        \\      acc = acc + i;
        \\    }}
        \\    assert(acc === x);
        \\  }}
        \\}}
        \\
    , .{bound});
}

/// Parse + validate + typecheck, returning the contract ready for pass 4.
fn frontend(alloc: std.mem.Allocator, source: []const u8) !types.ContractNode {
    const parsed = parse_ts.parseTs(alloc, source, "LoopBound.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;

    const val_result = try validate.validate(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    return tc_result.contract;
}

// Control: a normal small bound must keep compiling, and to the exact bytes it
// produced before the ceiling was added. These are the seven-tier agreed
// hexes; if a guard moves them, the guard is not byte-neutral and the change
// is a codegen regression, not a fix.
test "a valid loop bound still compiles byte-identically" {
    const cases = [_]struct { bound: []const u8, hex: []const u8 }{
        .{ .bound = "3", .hex = "537c9c" },
        .{ .bound = "10", .hex = "012d7c9c" },
    };
    for (cases) |tc| {
        for ([_]bool{ false, true }) |disable_folding| {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const alloc = arena.allocator();

            const source = try loopBoundSource(alloc, tc.bound);
            const result = try compiler_api.compileSourceWithOptions(
                alloc,
                source,
                "LoopBound.runar.ts",
                disable_folding,
            );
            try std.testing.expectEqualStrings(tc.hex, result.script_hex);
        }
    }
}

// The ceiling half of the fix. Every bound here fits an `i64` — and 10001 and
// 10^6 fit a `u32` too — so no amount of narrowing care stops them. Only
// MAX_LOOP_COUNT on the SOURCE path does. 2^63 - 1 and 2^32 + 5 are the two
// that used to reach `@intCast` with a value a `u32` cannot hold, i.e. the
// safety-checked panic.
test "a loop that unrolls past MAX_LOOP_COUNT is refused, naming the limit" {
    const bounds = [_][]const u8{
        "10001",
        "1000000",
        "4294967301", // 2^32 + 5 — the @intCast panic magnitude
        "9223372036854775807", // 2^63 - 1 — the largest bound the parser accepts
    };
    for (bounds) |bound| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const source = try loopBoundSource(alloc, bound);
        const contract = try frontend(alloc, source);

        var diag: anf_lower.LowerDiagnostic = .{};
        const result = anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);
        try std.testing.expectError(anf_lower.LowerError.LoopCountTooLarge, result);

        const message = diag.message orelse return error.TestExpectedDiagnostic;
        try std.testing.expect(std.mem.indexOf(u8, message, "loop count") != null);
        try std.testing.expect(std.mem.indexOf(u8, message, "10000") != null);
    }
}

// `compileSource` must propagate the typed refusal verbatim rather than
// flattening it into the anonymous `error.ANFLowerFailed`, so a caller can
// tell a loop-count refusal from any other pass-4 failure.
test "the full pipeline propagates the loop-count refusal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source = try loopBoundSource(alloc, "10001");
    try std.testing.expectError(
        error.LoopCountTooLarge,
        compiler_api.compileSource(std.testing.allocator, source, "LoopBound.runar.ts"),
    );
}

// A bound outside `i64` never reaches ANF lowering — the parsers route it to a
// `.literal_bigint` node, leaving `bound_is_const = false`, and pass 2 refuses
// it. The compile FAILS, which is what the seven-tier assertion requires; this
// test pins that it fails rather than silently unrolling something, and
// records that the diagnostic differs in wording from the other six tiers.
test "a loop bound outside i64 is refused before lowering" {
    const bounds = [_][]const u8{
        "9223372036854775808", // 2^63
        "18446744073709551626", // 2^64 + 10
        "100000000000000000000", // 10^20
    };
    for (bounds) |bound| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const source = try loopBoundSource(alloc, bound);
        const parsed = parse_ts.parseTs(alloc, source, "LoopBound.runar.ts");
        const contract = parsed.contract orelse return error.TestUnexpectedResult;

        const val_result = try validate.validate(alloc, contract);
        try std.testing.expect(val_result.errors.len > 0);

        try std.testing.expectError(
            error.ValidationFailed,
            compiler_api.compileSource(std.testing.allocator, source, "LoopBound.runar.ts"),
        );
    }
}
