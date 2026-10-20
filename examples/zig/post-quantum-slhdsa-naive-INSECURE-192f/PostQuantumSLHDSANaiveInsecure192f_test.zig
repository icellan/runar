const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumSLHDSANaiveInsecure192f = @import("PostQuantumSLHDSANaiveInsecure192f.runar.zig").PostQuantumSLHDSANaiveInsecure192f;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-slhdsa-naive-INSECURE-192f/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PostQuantumSLHDSANaiveInsecure192f.runar.zig" {
    try runCompileChecks("PostQuantumSLHDSANaiveInsecure192f.runar.zig");
}

// PEDAGOGY: intentionally broken pattern -- `msg` is a free spender-supplied argument, not bound to the transaction (see the contract header; the hybrid pattern lives in examples/zig/sphincs-wallet/).
// Proves: init stores the pubkey and spend() aborts when the SLH-DSA-SHA2-192f verifier rejects the (msg, sig) pair; the negative runs the real verifier on a malformed signature, which is fast.
// Does not prove: that a VALID signature is accepted (the runar Zig runtime has no SLH-DSA signer for these parameter sets, and a full-size verification is slow; the 192f verifier accepting a genuine signature is covered by the sphincs-wallet fixture for 128s only) or the 'anyone can spend' flaw itself.

test "PostQuantumSLHDSANaiveInsecure192f init stores the pubkey" {
    const pubkey = "slhdsa-pub-key-bytes-fake";
    const contract = PostQuantumSLHDSANaiveInsecure192f.init(pubkey);
    try std.testing.expectEqualSlices(u8, pubkey, contract.pubkey);
}

test "PostQuantumSLHDSANaiveInsecure192f spend rejects a malformed signature" {
    try root.expectAssertFailure("slhdsa-naive-192f-malformed-sig");
}
