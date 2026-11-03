//! N-321 — typecheck diagnostics must not echo an unbounded type text.
//!
//! What this proves: a typecheck diagnostic that echoes a 1 MB source name is
//! capped at 1024 bytes of message plus the `...(N more bytes elided)` marker,
//! and an ordinary diagnostic is unchanged. This tier's type echoes print an
//! enum tag (bounded by construction; an unknown type name is accepted here),
//! so the unbounded source text it can echo is an identifier: `Undefined
//! variable '<1 MB name>'`. What it does NOT prove: the other tiers
//! (conformance/negatives/n321-diagnostic-type-echo-parity.test.ts) nor each
//! echo site individually (the cap sits at the diagnostic sink).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const HEAD_A = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: bigint = ";
const HEAD_B = ";\n assert(q == this.t);\n }\n}\n";

fn run(a: std.mem.Allocator, type_text: []const u8) !compiler_api.Diagnostics {
    const src = try std.mem.concat(a, u8, &.{ HEAD_A, type_text, HEAD_B });
    var diag: compiler_api.Diagnostics = .{};
    _ = compiler_api.runPipeline(a, src, "P.runar.ts", .{}, &diag) catch {};
    return diag;
}

test "N-321 a 1 MB identifier is elided in typecheck diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const big = try a.alloc(u8, 1 << 20);
    @memset(big, 'T');
    const diag = try run(a, big);
    var echoing: usize = 0;
    for (diag.errors.items) |e| {
        if (std.mem.indexOf(u8, e, "TTTT") == null) continue;
        echoing += 1;
        try std.testing.expect(e.len < 1200);
        try std.testing.expect(std.mem.indexOf(u8, e, "...(") != null);
        try std.testing.expect(std.mem.endsWith(u8, e, " more bytes elided)"));
    }
    try std.testing.expect(echoing > 0);
}

test "N-321 an ordinary diagnostic is unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const diag = try run(a, "nope");
    var found = false;
    for (diag.errors.items) |e| {
        if (std.mem.indexOf(u8, e, "Undefined variable 'nope'") != null) found = true;
    }
    try std.testing.expect(found);
}
