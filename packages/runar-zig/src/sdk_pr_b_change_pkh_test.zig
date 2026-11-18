//! #213, SDK side — defence in depth only.
//!
//! A stateful method's unlocking script pushes the compiler-injected
//! `_changePKH` (a Ripemd160, exactly 20 bytes). The consensus defence is the
//! covenant's entry gate on its width (`OP_SIZE 0x14 OP_NUMEQUALVERIFY`).
//! `computeChangePkhHex` derives the change PKH as hash160(pubkey), always 20
//! bytes; `state_mod.encodeChangePkh` is the single encoder the change-PKH push
//! goes through, and refuses anything that is not exactly 20 bytes of hex with
//! `error.FixedWidthMismatch` (the N-045 error). `PreparedCall.change_pkh` is a
//! public field a caller can overwrite, so the refusal is also pinned through
//! `finalizeCall`. Proves nothing on chain.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const RunarContract = contract_mod.RunarContract;

fn hexOf(allocator: std.mem.Allocator, byte_pair: []const u8, n: usize) ![]u8 {
    const out = try allocator.alloc(u8, n * 2);
    for (0..n) |i| @memcpy(out[i * 2 .. i * 2 + 2], byte_pair);
    return out;
}

test "#213: encodeChangePkh refuses 19, 21, 54 bytes and non-hex, accepts exactly 20" {
    const allocator = std.testing.allocator;
    for ([_]usize{ 19, 21, 54 }) |n| {
        const v = try hexOf(allocator, "ab", n);
        defer allocator.free(v);
        try std.testing.expectError(error.FixedWidthMismatch, state_mod.encodeChangePkh(allocator, v));
    }
    const non_hex = try hexOf(allocator, "zz", 20);
    defer allocator.free(non_hex);
    try std.testing.expectError(error.FixedWidthMismatch, state_mod.encodeChangePkh(allocator, non_hex));

    const good = try hexOf(allocator, "ab", 20);
    defer allocator.free(good);
    const out = try state_mod.encodeChangePkh(allocator, good);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("14" ++ "ab" ** 20, out);
}

const ROOT_ARTIFACT_JSON =
    \\{"version":"runar-v0.1.0","contractName":"PrBRoot","parentClass":"StatefulSmartContract",
    \\ "abi":{"constructor":{"params":[{"name":"root","type":"Sha256"}]},
    \\  "methods":[{"name":"updateRoot","isPublic":true,"params":[
    \\   {"name":"nextRoot","type":"Sha256"},{"name":"_changePKH","type":"Ripemd160"},
    \\   {"name":"_changeAmount","type":"bigint"},{"name":"txPreimage","type":"SigHashPreimage"}]}]},
    \\ "script":"51","codeSeparatorIndex":0,
    \\ "stateFields":[{"name":"root","type":"Sha256","index":0}]}
;

const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

test "#213: finalizeCall refuses a caller-overwritten PreparedCall.change_pkh" {
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

    for ([_]usize{ 19, 21, 54 }) |n| {
        const args = [_]types.StateValue{.{ .bytes = "22" ** 32 }};
        const new_state = [_]types.StateValue{.{ .bytes = "22" ** 32 }};
        var prepared = try contract.prepareCall("updateRoot", &args, prov.provider(), signer.signer(), .{ .new_state = &new_state });
        defer prepared.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 40), prepared.change_pkh.len);
        allocator.free(prepared.change_pkh);
        prepared.change_pkh = try hexOf(allocator, "ab", n);
        try std.testing.expectError(
            error.FixedWidthMismatch,
            contract.finalizeCall(&prepared, &.{}, prov.provider()),
        );
    }
}
