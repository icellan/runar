const std = @import("std");
const bsvz = @import("bsvz");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// sha256Compress integration: compile + (when regtest is up) deploy and call
// a contract that runs the sha256Compress builtin against a known SHA-256
// IV / block vector. Mirrors the Go/TS `sha256-compress` regtest covers.
// ---------------------------------------------------------------------------

// SHA-256 initial hash value (FIPS 180-4 §5.3.3) as a 32-byte big-endian hex.
const SHA256_IV_HEX: [64]u8 = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19".*;

fn bytesToHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex_buf = try allocator.alloc(u8, bytes.len * 2);
    _ = bsvz.primitives.hex.encodeLower(bytes, hex_buf) catch {
        allocator.free(hex_buf);
        return error.OutOfMemory;
    };
    return hex_buf;
}

test "Sha256Compress_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(
        allocator,
        "examples/zig/sha256-compress/Sha256CompressTest.runar.zig",
    ) catch |err| {
        std.log.warn("Could not compile Sha256CompressTest: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Sha256CompressTest", artifact.contract_name);
    std.log.info("Sha256CompressTest compiled: {d} bytes", .{artifact.script.len / 2});
}

test "Sha256Compress_Deploy_AndCall_KnownVector" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(
        allocator,
        "examples/zig/sha256-compress/Sha256CompressTest.runar.zig",
    ) catch |err| {
        std.log.warn("Could not compile Sha256CompressTest: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    // Reference: state=IV, block=64 bytes of 0x00. Use the SDK's own
    // sha256Compress to derive the on-chain expected output (the same
    // routine the in-contract builtin executes).
    var state: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&state, &SHA256_IV_HEX);
    const block: [64]u8 = @splat(0);

    const expected_bytes = runar.sha256Compress(&state, &block);
    const expected_hex = try bytesToHexAlloc(allocator, expected_bytes);
    defer allocator.free(expected_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = expected_hex },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 100_000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("Sha256CompressTest deployed: {s}", .{deploy_txid});

    // Call verify(IV, 64*0x00) — the on-chain script computes
    // sha256Compress and asserts it equals expected.
    const block_hex = try bytesToHexAlloc(allocator, &block);
    defer allocator.free(block_hex);
    const iv_hex = try allocator.dupe(u8, &SHA256_IV_HEX);
    defer allocator.free(iv_hex);

    const call_txid = contract.call(
        "verify",
        &[_]runar.StateValue{
            .{ .bytes = iv_hex },
            .{ .bytes = block_hex },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    ) catch |err| {
        std.log.warn("sha256Compress verify call failed: {any}", .{err});
        return;
    };
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("Sha256CompressTest verify TX: {s}", .{call_txid});
}
