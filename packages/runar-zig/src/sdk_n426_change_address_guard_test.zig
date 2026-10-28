//! N-426 -- the stateful change-address guard. Replays the shared cross-SDK
//! vector `conformance/sdk-call/n426-change-address-guard.json` (TS reference,
//! Spend-validated in `conformance/sdk-call/n426-change-address-guard.test.ts`)
//! on the contract/UTXOs/key of `stateful-merge-prepared.json`.
//!
//! Proves: on a stateful method that takes `_changePKH`, `prepareCall` and
//! `call` refuse `change_address` for another key (no `change_pub_key`) with
//! `error.ChangeAddressMismatch`, record the shared message in
//! `sdk_errors.last_change_address_error`, and broadcast nothing;
//! `change_address` + the matching `change_pub_key` and `change_address`
//! equal to the signer's own address are accepted.
//! Does NOT prove: the terminal path, finalizeCall, or a live node.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");
const errors_mod = @import("sdk_errors.zig");

const DIR = "../../conformance/sdk-call/";

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

const Mode = enum { prepare, call };

/// Runs the vector's single-input stateful increment with `opts`; returns the
/// outcome and the number of broadcast txs.
fn run(opts: types.CallOptions, mode: Mode, broadcast_count: *usize) !void {
    const allocator = std.testing.allocator;
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, DIR ++ "stateful-merge-prepared.json", allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const v = parsed.value.object;

    const artifact_json = try std.json.Stringify.valueAlloc(allocator, v.get("artifact").?, .{});
    defer allocator.free(artifact_json);
    var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
    defer artifact.deinit();

    const cu = utxoOf(v.get("contractUtxo").?.object);
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

    var contract = try contract_mod.RunarContract.fromUtxo(allocator, &artifact, cu);
    defer contract.deinit();

    const args = [_]types.StateValue{.{ .int = 0 }};
    const new_count = try std.fmt.parseInt(i64, str(v.get("newState").?.object, "count"), 10);
    const new_state = [_]types.StateValue{.{ .int = new_count }};
    var o = opts;
    o.new_state = &new_state;
    defer broadcast_count.* = prov.getBroadcastedTxs().len;
    switch (mode) {
        .prepare => {
            var prepared = try contract.prepareCall("increment", &args, prov.provider(), signer.signer(), o);
            prepared.deinit(allocator);
        },
        .call => {
            const txid = try contract.call("increment", &args, prov.provider(), signer.signer(), o);
            allocator.free(txid);
        },
    }
}

fn loadGuard(allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, DIR ++ "n426-change-address-guard.json", allocator, .limited(1024 * 1024));
    defer allocator.free(raw);
    return std.json.parseFromSlice(std.json.Value, allocator, raw, .{ .allocate = .alloc_always });
}

fn expectRefused(mode: Mode) !void {
    const allocator = std.testing.allocator;
    const g = try loadGuard(allocator);
    defer g.deinit();
    const other = str(g.value.object, "otherAddress");
    const template = str(g.value.object, "message");
    const idx = std.mem.indexOf(u8, template, "{changeAddress}").?;
    const want = try std.mem.concat(allocator, u8, &.{ template[0..idx], other, template[idx + "{changeAddress}".len ..] });
    defer allocator.free(want);

    var n: usize = 99;
    try std.testing.expectError(error.ChangeAddressMismatch, run(.{ .change_address = other }, mode, &n));
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqualStrings(want, errors_mod.last_change_address_error.?.messageSlice());
}

test "N-426: prepareCall refuses change_address for another key without change_pub_key" {
    try expectRefused(.prepare);
}

test "N-426: call refuses change_address for another key without change_pub_key" {
    try expectRefused(.call);
}

test "N-426: change_address with the matching change_pub_key is accepted" {
    const g = try loadGuard(std.testing.allocator);
    defer g.deinit();
    var n: usize = 0;
    try run(.{
        .change_address = str(g.value.object, "otherAddress"),
        .change_pub_key = str(g.value.object, "otherPubKeyHex"),
    }, .prepare, &n);
    n = 0;
    try run(.{
        .change_address = str(g.value.object, "otherAddress"),
        .change_pub_key = str(g.value.object, "otherPubKeyHex"),
    }, .call, &n);
    try std.testing.expectEqual(@as(usize, 1), n);
}

test "N-426: change_address equal to the signer's own address is accepted" {
    const g = try loadGuard(std.testing.allocator);
    defer g.deinit();
    var n: usize = 0;
    try run(.{ .change_address = str(g.value.object, "ownAddress") }, .prepare, &n);
    try run(.{ .change_address = str(g.value.object, "ownAddress") }, .call, &n);
    try std.testing.expectEqual(@as(usize, 1), n);
}
