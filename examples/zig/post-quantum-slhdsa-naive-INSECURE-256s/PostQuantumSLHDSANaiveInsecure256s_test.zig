const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumSLHDSANaiveInsecure256s = @import("PostQuantumSLHDSANaiveInsecure256s.runar.zig").PostQuantumSLHDSANaiveInsecure256s;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-slhdsa-naive-INSECURE-256s/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PostQuantumSLHDSANaiveInsecure256s.runar.zig" {
    try runCompileChecks("PostQuantumSLHDSANaiveInsecure256s.runar.zig");
}

// PEDAGOGY: intentionally broken pattern -- `msg` is a free spender-supplied argument, not bound to the transaction (see the contract header; the hybrid pattern lives in examples/zig/sphincs-wallet/).
// Proves: init stores the pubkey and spend() aborts when the SLH-DSA-SHA2-256s verifier rejects the (msg, sig) pair; the negative runs the real verifier on a malformed signature, which is fast.
// Does not prove: that a VALID signature is accepted (the runar Zig runtime has no SLH-DSA signer for these parameter sets, and a full-size verification is slow; the 256s verifier accepting a genuine signature is covered by the sphincs-wallet fixture for 128s only) or the 'anyone can spend' flaw itself.

test "PostQuantumSLHDSANaiveInsecure256s init stores the pubkey" {
    const pubkey = "slhdsa-pub-key-bytes-fake";
    const contract = PostQuantumSLHDSANaiveInsecure256s.init(pubkey);
    try std.testing.expectEqualSlices(u8, pubkey, contract.pubkey);
}

test "PostQuantumSLHDSANaiveInsecure256s spend rejects a malformed signature" {
    try root.expectAssertFailure("slhdsa-naive-256s-malformed-sig");
}
