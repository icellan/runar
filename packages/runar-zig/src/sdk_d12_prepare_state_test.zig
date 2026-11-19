//! D12 SDK-F2: an abandoned or superseded PreparedCall must not leave the
//! tracked state advanced. `prepareCall` applied `CallOptions.new_state` to
//! `self.state` and kept it there; a second prepare then snapshotted the first
//! one's post-state as its `state_before`, so a failed finalize "restored" a
//! state the chain never reached. Semantics now (all tiers): prepareCall never
//! changes the tracked state; the post-state travels in the PreparedCall and
//! finalizeCall commits it only after a successful broadcast.
//!
//! Proves: prepare A (new_state 42) leaves state 0; prepare B (new_state 43)
//! leaves state 0; a failing finalize of B leaves state 0; finalize A commits 42.
//! Does NOT prove: on-chain acceptance (Zig ships no ScriptVM).

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const ARTIFACT_JSON = @embedFile("fixtures/n189-sclen-artifact.json");
const KEY = "00" ** 31 ++ "05";
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

test "D12 SDK-F2: prepareCall never advances the tracked state" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();
    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex(KEY);
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try prov.addUtxo(addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
        try prov.addUtxo(addr, .{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }
    const ctor = [_]types.StateValue{.{ .int = 0 }};
    var contract = try contract_mod.RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();
    const deploy_txid = try contract.deploy(prov.provider(), signer.signer(), .{ .satoshis = 10_000 });
    defer allocator.free(deploy_txid);

    const args = [_]types.StateValue{};
    const ns_a = [_]types.StateValue{.{ .int = 42 }};
    const ns_b = [_]types.StateValue{.{ .int = 43 }};

    var a = try contract.prepareCall("rec", &args, prov.provider(), signer.signer(), .{ .new_state = &ns_a });
    defer a.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 0), contract.state[0].int);

    var b = try contract.prepareCall("rec", &args, prov.provider(), signer.signer(), .{ .new_state = &ns_b });
    defer b.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 0), contract.state[0].int);

    // A failing finalize (wrong signature count) of B must not rewind or
    // advance anything.
    const bogus = [_][]const u8{"00"};
    try std.testing.expectError(contract_mod.ContractError.SignatureCountMismatch, contract.finalizeCall(&b, &bogus, prov.provider()));
    try std.testing.expectEqual(@as(i64, 0), contract.state[0].int);

    const txid = try contract.finalizeCall(&a, &.{}, prov.provider());
    defer allocator.free(txid);
    try std.testing.expectEqual(@as(i64, 42), contract.state[0].int);
}
