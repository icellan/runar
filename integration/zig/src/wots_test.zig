const std = @import("std");
const bsvz = @import("bsvz");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// WOTS+ integration: compile + (when regtest is up) deploy and call the
// "raw" WOTS+ verify contract using a deterministic keypair / signature
// produced from the runar.testing helpers. Mirrors the Go/TS `wots`
// regtest covers.
//
// The contract under test is examples/zig/post-quantum-wots-naive-INSECURE/
// — a minimal teaching contract that exposes verifyWOTS as a spending
// condition. The real PQ wallet pattern is exercised in the existing
// post_quantum_wallet_test.zig regtest.
// ---------------------------------------------------------------------------

fn bytesToHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex_buf = try allocator.alloc(u8, bytes.len * 2);
    _ = bsvz.primitives.hex.encodeLower(bytes, hex_buf) catch {
        allocator.free(hex_buf);
        return error.OutOfMemory;
    };
    return hex_buf;
}

test "WOTS_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure.runar.zig",
    );
    defer artifact.deinit();

    try std.testing.expectEqualStrings("PostQuantumWOTSNaiveInsecure", artifact.contract_name);
    // WOTS+ verify inlined script is large (~10 KB).
    try std.testing.expect(artifact.script.len / 2 > 5000);
    std.log.info("PostQuantumWOTSNaiveInsecure compiled: {d} bytes", .{artifact.script.len / 2});
}

test "WOTS_Deploy_AndCall_DeterministicVector" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure.runar.zig",
    );
    defer artifact.deinit();

    // Deterministic WOTS+ keypair for the test.
    const seed = [_]u8{0xAA} ** 32;
    const pub_seed = [_]u8{0xBB} ** 32;
    const message = "hello wots integration";

    const pk = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    const sig = runar.testing.wotsSignDeterministic(message, &seed, &pub_seed);

    const pk_hex = try bytesToHexAlloc(allocator, &pk);
    defer allocator.free(pk_hex);
    const sig_hex = try bytesToHexAlloc(allocator, &sig);
    defer allocator.free(sig_hex);
    const msg_hex = try bytesToHexAlloc(allocator, message);
    defer allocator.free(msg_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500_000 });
    defer allocator.free(deploy_txid);
    std.log.info("WOTS contract deployed: {s}", .{deploy_txid});

    const call_txid = try contract.call(
        "spend",
        &[_]runar.StateValue{
            .{ .bytes = msg_hex },
            .{ .bytes = sig_hex },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("WOTS spend TX: {s}", .{call_txid});
}
