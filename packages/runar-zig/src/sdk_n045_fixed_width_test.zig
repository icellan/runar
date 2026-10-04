//! N-045 (EXT-2 WideHash), SDK side — defence in depth only.
//!
//! The on-chain state reader slices each fixed-width byte field at its
//! declared width, so a wrong-width value in a state section shifts every
//! later field. The consensus defence is the covenant's own
//! `OP_SIZE <width> OP_NUMEQUALVERIFY` before each continuation commit (proved
//! under strict Spend in
//! packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts).
//! These tests pin the off-chain refusals: `serializeState` and `call` /
//! `prepareCall` reject a wrong-width fixed-width value with
//! `error.FixedWidthMismatch`. (Constructor args are deliberately NOT checked:
//! the other SDKs' `fromUtxo` build their contract with placeholder
//! constructor args, and every tier keeps the same surface. A mutable field's
//! deploy-time value still goes through `serializeState`.) They prove nothing
//! on chain.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const RunarContract = contract_mod.RunarContract;

const TypeWidth = struct { name: []const u8, width: usize };
const TYPES = [_]TypeWidth{
    .{ .name = "PubKey", .width = 33 },    .{ .name = "Sha256", .width = 32 },
    .{ .name = "Ripemd160", .width = 20 }, .{ .name = "Addr", .width = 20 },
    .{ .name = "Point", .width = 64 },     .{ .name = "P256Point", .width = 64 },
    .{ .name = "P384Point", .width = 96 },
};

fn hexOf(allocator: std.mem.Allocator, byte_pair: []const u8, n: usize) ![]u8 {
    const out = try allocator.alloc(u8, n * 2);
    for (0..n) |i| @memcpy(out[i * 2 .. i * 2 + 2], byte_pair);
    return out;
}

test "N-045: serializeState refuses a wrong-width fixed-width value and accepts the exact width" {
    const allocator = std.testing.allocator;
    for (TYPES) |t| {
        const fields = [_]types.StateField{.{ .name = "k", .type_name = t.name, .index = 0 }};
        for ([_]usize{ t.width - 1, t.width + 1 }) |bad| {
            const v = try hexOf(allocator, "ab", bad);
            defer allocator.free(v);
            const vals = [_]types.StateValue{.{ .bytes = v }};
            try std.testing.expectError(error.FixedWidthMismatch, state_mod.serializeState(allocator, &fields, &vals));
        }
        const non_hex = try hexOf(allocator, "zz", t.width);
        defer allocator.free(non_hex);
        const nh_vals = [_]types.StateValue{.{ .bytes = non_hex }};
        try std.testing.expectError(error.FixedWidthMismatch, state_mod.serializeState(allocator, &fields, &nh_vals));

        const good = try hexOf(allocator, "ab", t.width);
        defer allocator.free(good);
        const good_vals = [_]types.StateValue{.{ .bytes = good }};
        const out = try state_mod.serializeState(allocator, &fields, &good_vals);
        defer allocator.free(out);
        try std.testing.expectEqualStrings(good, out);
    }
}

const ROOT_ARTIFACT_JSON =
    \\{"version":"runar-v0.1.0","contractName":"N045Root","parentClass":"StatefulSmartContract",
    \\ "abi":{"constructor":{"params":[{"name":"root","type":"Sha256"}]},
    \\  "methods":[{"name":"updateRoot","isPublic":true,"params":[
    \\   {"name":"nextRoot","type":"Sha256"},{"name":"_changePKH","type":"Ripemd160"},
    \\   {"name":"_changeAmount","type":"bigint"},{"name":"txPreimage","type":"SigHashPreimage"}]}]},
    \\ "script":"51","codeSeparatorIndex":0,
    \\ "stateFields":[{"name":"root","type":"Sha256","index":0}]}
;

const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

test "N-045: call and prepareCall refuse a wrong-width Sha256 argument" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, ROOT_ARTIFACT_JSON);
    defer artifact.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex("00" ** 31 ++ "0b");
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try prov.addUtxo(addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }

    const ctor = [_]types.StateValue{.{ .bytes = "11" ** 32 }};
    var contract = try RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();
    const txid = try contract.deploy(prov.provider(), signer.signer(), .{ .satoshis = 50_000 });
    defer allocator.free(txid);

    for ([_]usize{ 31, 33, 66 }) |bad| {
        const v = try hexOf(allocator, "22", bad);
        defer allocator.free(v);
        const args = [_]types.StateValue{.{ .bytes = v }};
        try std.testing.expectError(
            error.FixedWidthMismatch,
            contract.call("updateRoot", &args, prov.provider(), signer.signer(), null),
        );
        try std.testing.expectError(
            error.FixedWidthMismatch,
            contract.prepareCall("updateRoot", &args, prov.provider(), signer.signer(), null),
        );
    }
}
