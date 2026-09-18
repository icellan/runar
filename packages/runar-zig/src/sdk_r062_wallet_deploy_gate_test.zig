//! R-062 — the unsound-primitive deploy gate on the WALLET funding path (Zig).
//!
//! Zig is the tier that was already correct: `deployWithWallet` is a thin
//! wrapper that builds a WalletProvider + WalletSigner and delegates to
//! `contract.deploy`, which runs both the DoS script-size bound and the
//! unsound-primitive gate. The reported bypass does NOT exist here, and these
//! tests pin that so a future refactor cannot quietly re-open it.
//!
//! What Zig DID lack is the other half of parity: the wallet path had no way to
//! SUPPLY an acknowledgement, so a legitimate acknowledged deploy was refused
//! (over-rejection, not under-rejection). `acknowledge_unsound` on the
//! `deployWithWallet` options closes that, with the same mechanism and the same
//! error as `DeployOptions.acknowledge_unsound`.

const std = @import("std");
const types = @import("sdk_types.zig");
const contract_mod = @import("sdk_contract.zig");
const wallet_mod = @import("sdk_wallet.zig");
const errors_mod = @import("sdk_errors.zig");

/// The P2PKH script for MockWalletClient's deterministic pubkey — the funding
/// UTXO the wallet-backed deploy must find and spend.
const MOCK_PUB_KEY = "02" ++ "00" ** 32;

fn artifactJson(comptime unsound: []const u8) []const u8 {
    return "{\"version\":\"runar-v1.0.0-rc.1\",\"contractName\":\"Sp1Rollup\",\"script\":\"51\"" ++
        unsound ++ "}";
}

const UNSOUND = ",\"unsoundPrimitives\":[\"verifySP1FRI\"]";

fn fundedWallet(allocator: std.mem.Allocator, mock: *wallet_mod.MockWalletClient) !void {
    // The funding coin must be scripted to hash160(MOCK_PUB_KEY), which is what
    // `deployWithWallet` derives for the provider's expected-script filter.
    // Computed here from the key itself, not via the SDK's script builder, so a
    // bug in that builder cannot make this control vacuously agree with it.
    const bsvz = @import("bsvz");
    var pub_key_bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pub_key_bytes, MOCK_PUB_KEY);
    const ripe = bsvz.crypto.hash.hash160(&pub_key_bytes);
    var pkh_hex: [40]u8 = undefined;
    _ = try bsvz.primitives.hex.encodeLower(&ripe.bytes, &pkh_hex);
    const script = try std.fmt.allocPrint(allocator, "76a914{s}88ac", .{pkh_hex});
    defer allocator.free(script);
    const outpoint = try std.fmt.allocPrint(allocator, "{s}.0", .{"ab" ** 32});
    defer allocator.free(outpoint);
    try mock.addOutput(.{
        .outpoint = outpoint,
        .satoshis = 100_000,
        .locking_script = script,
        .spendable = true,
    });
}

fn runWalletDeploy(
    allocator: std.mem.Allocator,
    comptime unsound: []const u8,
    acknowledge: []const []const u8,
) ![]u8 {
    var mock = wallet_mod.MockWalletClient.init(allocator);
    defer mock.deinit();
    try fundedWallet(allocator, &mock);

    var artifact = try types.RunarArtifact.fromJson(allocator, artifactJson(unsound));
    defer artifact.deinit();

    var contract = try contract_mod.RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    return wallet_mod.deployWithWallet(&contract, mock.walletClient(), .{
        .satoshis = 1,
        .basket = "test-basket",
        .protocol_id = .{ .level = 2, .name = "test" },
        .key_id = "1",
        .acknowledge_unsound = acknowledge,
    });
}

test "R-062 zig: deployWithWallet refuses an unacknowledged unsound artifact" {
    const allocator = std.testing.allocator;
    errors_mod.last_unsound = null;

    try std.testing.expectError(
        error.UnsoundPrimitiveNotAcknowledged,
        runWalletDeploy(allocator, UNSOUND, &.{}),
    );

    const rec = errors_mod.last_unsound orelse return error.TestExpectedRecordedContext;
    try std.testing.expectEqualStrings("verifySP1FRI", rec.primitiveSlice());
    try std.testing.expectEqualStrings("Sp1Rollup.deploy", rec.contextSlice());
}

test "R-062 zig CONTROL: an ordinary artifact still funds through the wallet path" {
    const allocator = std.testing.allocator;
    const txid = try runWalletDeploy(allocator, "", &.{});
    defer allocator.free(txid);
    try std.testing.expect(txid.len > 0);
}

test "R-062 zig CONTROL: an acknowledged unsound artifact still funds through the wallet path" {
    const allocator = std.testing.allocator;
    const ack: []const []const u8 = &.{"verifySP1FRI"};
    const txid = try runWalletDeploy(allocator, UNSOUND, ack);
    defer allocator.free(txid);
    try std.testing.expect(txid.len > 0);
}

test "R-062 zig: a PARTIAL acknowledgement is still a refusal" {
    const allocator = std.testing.allocator;
    errors_mod.last_unsound = null;
    const ack: []const []const u8 = &.{"somethingElse"};
    try std.testing.expectError(
        error.UnsoundPrimitiveNotAcknowledged,
        runWalletDeploy(allocator, UNSOUND, ack),
    );
    const rec = errors_mod.last_unsound orelse return error.TestExpectedRecordedContext;
    try std.testing.expectEqualStrings("verifySP1FRI", rec.primitiveSlice());
}
