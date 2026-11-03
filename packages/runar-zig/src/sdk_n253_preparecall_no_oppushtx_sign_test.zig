//! N-253 -- since F-369/N-213 the k=1 OP_PUSH_TX ECDSA signature is unused on
//! the stateful prepareCall/call path (`buildStatefulUnlockScript` ignores it;
//! the on-chain script derives it from the preimage), yet the path still
//! computed and discarded one per pass. The fix adds
//! `computeOpPushTxPreimageWithSigHash` and uses it there; `computeOpPushTx*`
//! stay public and unchanged.
//!
//! Proves: a stateful merge prepareCall (the shared N-286 vector: primary +
//! extra contract input) performs zero OP_PUSH_TX signs, counted through
//! `oppushtx.sign_count`; the control shows the counter sees
//! `computeOpPushTxWithSigHash` sign and that the preimage-only variant returns
//! the identical preimage without signing. Byte-identity of prepareCall output
//! is proven by sdk_n286_stateful_merge_prepared_test.zig. Says nothing about
//! the stateless / terminal paths.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");
const oppushtx = @import("sdk_oppushtx.zig");

const VECTOR_PATH = "../../conformance/sdk-call/stateful-merge-prepared.json";

fn str(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    return obj.get(key).?.string;
}

fn utxoOf(obj: std.json.ObjectMap) types.UTXO {
    return .{
        .txid = str(obj, "txid"),
        .output_index = @intCast(obj.get("outputIndex").?.integer),
        .satoshis = obj.get("satoshis").?.integer,
        .script = str(obj, "script"),
    };
}

test "N-253: stateful prepareCall computes no OP_PUSH_TX signature" {
    const allocator = std.testing.allocator;
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, VECTOR_PATH, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const v = parsed.value.object;
    const expected = v.get("expected").?.object;

    const artifact_json = try std.json.Stringify.valueAlloc(allocator, v.get("artifact").?, .{});
    defer allocator.free(artifact_json);
    var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
    defer artifact.deinit();

    const cu = utxoOf(v.get("contractUtxo").?.object);
    const eu = utxoOf(v.get("extraContractUtxo").?.object);
    const fu = utxoOf(v.get("fundingUtxo").?.object);

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex(str(v, "privKeyHex"));
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try prov.addUtxo(addr, fu);
    }
    try prov.addKnownOutpoint(cu.txid, cu.output_index, cu.script, cu.satoshis);
    try prov.addKnownOutpoint(eu.txid, eu.output_index, eu.script, eu.satoshis);

    var contract = try contract_mod.RunarContract.fromUtxo(allocator, &artifact, cu);
    defer contract.deinit();

    const args = [_]types.StateValue{.{ .int = 0 }};
    const extra = [_]types.UTXO{eu};
    const new_count = try std.fmt.parseInt(i64, str(v.get("newState").?.object, "count"), 10);
    const new_state = [_]types.StateValue{.{ .int = new_count }};

    const before = oppushtx.sign_count;
    var prepared = try contract.prepareCall("increment", &args, prov.provider(), signer.signer(), .{
        .additional_contract_inputs = &extra,
        .new_state = &new_state,
    });
    defer prepared.deinit(allocator);
    try std.testing.expectEqualStrings(str(expected, "sighash"), prepared.sighashes[0]);
    try std.testing.expectEqual(@as(usize, 0), oppushtx.sign_count - before);

    // Control: the signing helper bumps the counter; the preimage-only variant
    // returns the same preimage and does not.
    const tx_hex = str(expected, "referenceTxHex");
    for ([_]u32{ 0x41, 0x43 }) |flag| {
        const b = oppushtx.sign_count;
        var full = try oppushtx.computeOpPushTxWithSigHash(allocator, tx_hex, 0, cu.script, cu.satoshis, -1, flag);
        defer full.deinit(allocator);
        try std.testing.expectEqual(b + 1, oppushtx.sign_count);
        var only = try oppushtx.computeOpPushTxPreimageWithSigHash(allocator, tx_hex, 0, cu.script, cu.satoshis, -1, flag);
        defer only.deinit(allocator);
        try std.testing.expectEqual(b + 1, oppushtx.sign_count);
        try std.testing.expectEqualStrings(full.preimage_hex, only.preimage_hex);
    }
    try std.testing.expectError(
        error.EmptySubscript,
        oppushtx.computeOpPushTxPreimageWithSigHash(allocator, tx_hex, 0, "", 1, -1, 0x41),
    );
}
