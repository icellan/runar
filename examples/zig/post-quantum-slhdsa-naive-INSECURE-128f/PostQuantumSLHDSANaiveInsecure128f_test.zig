const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumSLHDSANaiveInsecure128f = @import("PostQuantumSLHDSANaiveInsecure128f.runar.zig").PostQuantumSLHDSANaiveInsecure128f;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-slhdsa-naive-INSECURE-128f/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PostQuantumSLHDSANaiveInsecure128f.runar.zig" {
    try runCompileChecks("PostQuantumSLHDSANaiveInsecure128f.runar.zig");
}

// PEDAGOGY: intentionally broken pattern -- `msg` is a free spender-supplied argument, not bound to the transaction (see the contract header; the hybrid pattern lives in examples/zig/sphincs-wallet/).
// Proves: init stores the pubkey and spend() aborts when the SLH-DSA-SHA2-128f verifier rejects the (msg, sig) pair; the negative runs the real verifier on a malformed signature, which is fast.
// Does not prove: that a VALID signature is accepted (the runar Zig runtime has no SLH-DSA signer for these parameter sets, and a full-size verification is slow; the 128f verifier accepting a genuine signature is covered by the sphincs-wallet fixture for 128s only) or the 'anyone can spend' flaw itself.

test "PostQuantumSLHDSANaiveInsecure128f init stores the pubkey" {
    const pubkey = "slhdsa-pub-key-bytes-fake";
    const contract = PostQuantumSLHDSANaiveInsecure128f.init(pubkey);
    try std.testing.expectEqualSlices(u8, pubkey, contract.pubkey);
}

test "PostQuantumSLHDSANaiveInsecure128f spend rejects a malformed signature" {
    try root.expectAssertFailure("slhdsa-naive-128f-malformed-sig");
}
