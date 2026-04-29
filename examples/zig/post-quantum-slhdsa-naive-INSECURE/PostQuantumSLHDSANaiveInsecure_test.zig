const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumSLHDSANaiveInsecure = @import("PostQuantumSLHDSANaiveInsecure.runar.zig").PostQuantumSLHDSANaiveInsecure;

// PEDAGOGY: intentionally broken pattern -- "anyone can spend" once a single
// (msg, sig) pair under `pubkey` is observed, because `msg` is supplied by
// the spender and is not bound to the spending transaction. See the source
// file header for a full explanation. The hybrid pattern lives in
// examples/zig/sphincs-wallet/.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-slhdsa-naive-INSECURE/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PostQuantumSLHDSANaiveInsecure.runar.zig" {
    try runCompileChecks("PostQuantumSLHDSANaiveInsecure.runar.zig");
}

test "PostQuantumSLHDSANaiveInsecure init stores the pubkey" {
    // The runar Zig runtime does not expose an SLH-DSA keygen helper, so we
    // cannot natively demonstrate the flaw end-to-end here -- the pedagogical
    // proof of "anyone can spend" lives in the Python and Ruby tiers. The
    // compile-check above plus this construction sanity check are what the
    // Zig tier offers; the full hybrid pattern is exercised under
    // examples/zig/sphincs-wallet/.
    const pubkey = "slhdsa-pub-key-bytes-fake";
    const contract = PostQuantumSLHDSANaiveInsecure.init(pubkey);
    try std.testing.expectEqualSlices(u8, pubkey, contract.pubkey);
}
