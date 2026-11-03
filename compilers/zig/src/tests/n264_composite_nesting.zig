//! N-264 — call depth x nesting must not overflow the host stack.
//!
//! Private methods are inlined at every call site, so F-213's per-method
//! nesting bound (128) and N-180's call-depth bound (128) compose
//! multiplicatively: a chain of D helpers that each call the next under K
//! nested ifs is D*K nested ifs after inlining. This tier segfaulted (stack
//! overflow in stack_lower's if-lowering) at D=16 x 120. User decision R106:
//! lower iteratively, with an explicit work stack.
//!
//! The source is remediation-logs/N-180/compgen.py's shape. The pinned digests
//! are sha256 of the script hex the UNMODIFIED Go compiler printed for the same
//! source (at 5b75534ec, before any N-264 change): goroutine stacks grow, so Go
//! compiled every depth, and its D=8 output was byte-identical to all six other
//! tiers'.
//!
//! Proves: this tier compiles D=32 x 120 (3,840 nested ifs), byte-identical to
//! Go. A stack overflow kills this whole test binary rather than failing one
//! test.
//! Does not prove: the deepest admissible chain, D=127 x 120. Its memory
//! blow-up (the compile arena kept a copy of every spliced arm per enclosing
//! if) is N-280's, bounded in tests/n280_composite_nesting_memory.zig; D=127
//! itself is pinned against the CLI in conformance/negatives/
//! n264-composite-nesting-parity.test.ts, too slow for this Debug suite. Nor
//! does it prove the other tiers (conformance/negatives/
//! n264-composite-nesting-parity.test.ts drives all seven CLIs), or that Go's
//! deep output is right beyond agreeing with every tier at D=8.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// remediation-logs/N-180/compgen.py, verbatim.
pub fn comp(w: std.mem.Allocator, d: usize, k: usize) ![]const u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    try b.appendSlice(w, "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
    for (0..d) |i| {
        try b.appendSlice(w, try std.fmt.allocPrint(w, " private m{d}(x: bigint): bigint {{\n", .{i}));
        try b.appendSlice(w, "  let r: bigint = x;\n");
        for (0..k) |j| try b.appendSlice(w, try std.fmt.allocPrint(w, "  if (x > {d}n) {{\n", .{j}));
        try b.appendSlice(w, try std.fmt.allocPrint(w, "  r = this.m{d}(x);\n", .{i + 1}));
        for (0..k) |_| try b.appendSlice(w, "  }\n");
        try b.appendSlice(w, "  return r;\n }\n");
    }
    try b.appendSlice(w, try std.fmt.allocPrint(w, " private m{d}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n", .{d}));
    return b.items;
}

fn expectGoDigest(d: usize, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();
    const file = try std.fmt.allocPrint(w, "comp{d}k120.runar.ts", .{d});
    const hex = try compiler_api.compileSourceToHex(w, try comp(w, d, 120), file);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(hex, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings(want, &got);
}

test "N-264: D=32 x 120 compiles byte-identically to Go" {
    // N-216 (2026-10-21): re-pinned to the post-fix Go output (D=32: 30586 -> 30525 B, D=127: 121406 -> 121155 B); the opcode diff vs the 5b75534ec pin is only the branch-reconcile `<k> OP_ROLL` -> OP_SWAP / OP_ROT folds.
    try expectGoDigest(32, "84c53e49c0d144c35d8db922859dd52fd71590d0c2e6ebea5b82501593301ec8");
}
