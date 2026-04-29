const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumWOTSNaiveInsecure = @import("PostQuantumWOTSNaiveInsecure.runar.zig").PostQuantumWOTSNaiveInsecure;

// PEDAGOGY: intentionally broken pattern -- "anyone can spend" once a single
// (msg, sig) pair under `pubkey` is observed, because `msg` is supplied by
// the spender and is not bound to the spending transaction. See the source
// file header for a full explanation. The hybrid pattern lives in
// examples/zig/post-quantum-wallet/.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-wots-naive-INSECURE/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PostQuantumWOTSNaiveInsecure.runar.zig" {
    try runCompileChecks("PostQuantumWOTSNaiveInsecure.runar.zig");
}

test "PostQuantumWOTSNaiveInsecure init stores the pubkey" {
    const pubkey = "wots-pub-key-bytes-fake";
    const contract = PostQuantumWOTSNaiveInsecure.init(pubkey);
    try std.testing.expectEqualSlices(u8, pubkey, contract.pubkey);
}

test "PostQuantumWOTSNaiveInsecure: any (msg, sig) pair under pubkey passes (the bug)" {
    // Demonstrate the flaw: the contract accepts any attacker-chosen msg
    // signed under the legitimate WOTS+ key. There is no transaction
    // binding, so anyone with a (msg, sig) pair can spend.
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);

    const contract = PostQuantumWOTSNaiveInsecure.init(&wots_pub_key);

    // Attacker picks an arbitrary message and signs it themselves.
    const arbitrary_msg = "anyone-can-spend-with-this-message";
    const arbitrary_sig = runar.testing.wotsSignDeterministic(arbitrary_msg, &seed, &pub_seed);
    contract.spend(arbitrary_msg, &arbitrary_sig);

    // A totally different attacker-chosen message also works.
    const other_msg = "another-totally-different-payload";
    const other_sig = runar.testing.wotsSignDeterministic(other_msg, &seed, &pub_seed);
    contract.spend(other_msg, &other_sig);
}
