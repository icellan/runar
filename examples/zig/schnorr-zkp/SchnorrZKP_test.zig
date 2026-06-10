const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");

// BUG-001: native execution of SchnorrZKP is disabled in the Zig tier.
// The contract embeds the secp256k1 group order (256 bits) as a Rúnar
// bigint literal in `assert(within(s, 1, <n>))`. runar.Bigint = i64 in
// Zig — Zig's compiler rejects the comptime_int → i64 coercion at
// build time, so `@import("SchnorrZKP.runar.zig")` itself fails to
// compile.
//
// The Rúnar frontend reads this file as text and lowers the literal to
// a 32-byte little-endian push in the emitted Bitcoin Script, which is
// what the on-chain verifier executes. The TS/Sol/Move/Python tests
// (in examples/{ts,sol,move,python}/schnorr-zkp/) exercise the full
// algebraic semantics with arbitrary-precision arithmetic; this file
// is kept as a Rúnar compile-check only.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "schnorr-zkp/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check SchnorrZKP.runar.zig" {
    try runCompileChecks("SchnorrZKP.runar.zig");
}
