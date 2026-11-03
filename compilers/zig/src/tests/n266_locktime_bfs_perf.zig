//! N-266: `warnLocktimeWithoutSequenceGuard` (passes/validate.zig) runs a BFS
//! over the private-helper call graph once per public method and, for every
//! callee it follows, used to re-scan `contract.methods` **linearly** to find
//! the matching `MethodNode`. On a chain of D private helpers that call-graph
//! walk is O(D) BFS steps times an O(D) linear scan per step = O(D^2). The
//! other tiers that implement the same BFS (e.g.
//! `compilers/go/frontend/validator.go`'s `warnLocktimeWithoutSequenceGuard`,
//! `compilers/rust/src/frontend/validator.rs`'s
//! `warn_locktime_without_sequence_guard`) build a name -> private-method hash
//! map once per call instead, so the same walk is O(D).
//!
//! Proves: validating a 20000-link private-helper chain
//! (`verify -> m0 -> m1 -> ... -> m20000`, generated the same way as N-180's
//! `chain()` in `n180_call_depth_limit.zig`) stays comfortably under a
//! 1-second CPU budget, AND produces the exact same (empty) set of locktime
//! warnings the slow version produced. The chain never reads
//! `extractLocktime` anywhere, so the warning set is a fixed point across the
//! fix: this is a pure CPU-time regression test, not a diagnostic-content
//! test. Measures the process CPU-time clock (`std.Io.Clock.cpu_process`)
//! rather than wall-clock time, so it is not sensitive to unrelated load on a
//! shared CI box.
//!
//! Does not prove: anything about warning CONTENT on a chain that DOES read
//! extractLocktime (covered by the "H2: ..." tests next to
//! `warnLocktimeWithoutSequenceGuard` in `passes/validate.zig`), the exact
//! constant factor the fix achieves, or that any other tier shares this bug.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// A chain of `n` private helpers `m0 -> m1 -> ... -> mn` (the last one
/// returns its argument unchanged), plus one public entry point `verify`
/// calling `m0`. Mirrors the `.ts` branch of `n180_call_depth_limit.zig`'s
/// `chain()` helper (duplicated rather than imported: that helper is
/// file-private and this file must not touch N-180's test).
fn chainOfPrivateHelpers(w: std.mem.Allocator, n: usize) ![]const u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    try b.appendSlice(w, "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
    for (0..n) |i| {
        try b.appendSlice(w, try std.fmt.allocPrint(w, " private m{d}(x: bigint): bigint {{ return this.m{d}(x); }}\n", .{ i, i + 1 }));
    }
    try b.appendSlice(w, try std.fmt.allocPrint(
        w,
        " private m{d}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n",
        .{n},
    ));
    return b.items;
}

test "N-266: the locktime-warning BFS on a 20000-link private-helper chain stays under a 1s CPU budget" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();
    const io = std.testing.io;

    const src = try chainOfPrivateHelpers(w, 20000);
    const parsed = compiler_api.parseSource(w, src, "P.runar.ts");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const contract = parsed.contract orelse return error.TestFixtureDidNotParse;

    const start = std.Io.Clock.cpu_process.now(io);
    const result = try compiler_api.validateForFile(w, contract, "P.runar.ts");
    const elapsed = start.durationTo(std.Io.Clock.cpu_process.now(io));

    // The chain never calls extractLocktime, so the fix must not change the
    // (empty) warning set it produces -- this test is about CPU time spent,
    // not about what gets warned.
    try std.testing.expectEqual(@as(usize, 0), result.warnings.len);

    const elapsed_ms = elapsed.toMilliseconds();
    if (elapsed_ms >= 1000) {
        std.debug.print(
            "  validate() on a 20000-link private-helper chain took {d}ms of CPU time (budget: 1000ms)\n",
            .{elapsed_ms},
        );
        return error.LocktimeBfsTooSlow;
    }
}
