//! N-295 — Zig `call()`'s funding-candidate filter for a stateful merge
//! excluded only the primary contract UTXO (`contract_utxo`), not any
//! `options.additional_contract_inputs` outpoint (sdk_contract.zig, the
//! non-terminal branch around "Filter out the contract UTXO from funding
//! UTXOs"). Mirrors Java's N-294
//! (`AdditionalContractInputsTest#mergeNeverSelectsTheAdditionalContractUtxoAsFunding`)
//! and TS's F-045.
//!
//! Scenario: a merge spends TWO contract UTXOs (the primary + one
//! `additional_contract_inputs` entry) and a P2PKH funding UTXO. An indexer
//! ALSO lists the extra contract UTXO at the signer's own P2PKH address —
//! exactly what a real indexer does when a covenant output happens to use a
//! script an indexer attributes to the owning key. The extra UTXO carries a
//! LARGE satoshi value so the SDK's largest-first funding coin selection
//! prefers it over the small genuine funding coin, if the filter fails to
//! exclude it.
//!
//! Proves: the extra contract UTXO's outpoint (txid:vout) appears exactly
//! ONCE among the broadcast tx's inputs — as the additional contract input —
//! never a second time as a P2PKH funding input. Before the fix, Zig's
//! `additional_utxos` filter checked only `contract_utxo`, so the extra
//! outpoint was both unlocked as a contract input AND selected again as
//! funding: a double-spend of the same outpoint within one transaction.
//! `MockProvider.validateBroadcast` does not catch this — it sums
//! `known_outpoints` per INPUT, so a repeated outpoint silently double-counts
//! value instead of being rejected (same blind spot the Java bug report
//! describes).
//!
//! Does NOT prove: on-chain acceptance (Zig ships no ScriptVM — see
//! CLAUDE.md); more than one colliding extra input; the Zig two-phase
//! prepareCall/finalizeCall merge (N-286); a live node.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const VECTOR_PATH = "../../conformance/sdk-call/stateful-merge-prepared.json";

fn str(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    return obj.get(key).?.string;
}

fn readVarint(bytes: []const u8, pos: *usize) u64 {
    const first = bytes[pos.*];
    pos.* += 1;
    switch (first) {
        0xfd => {
            const v = std.mem.readInt(u16, bytes[pos.*..][0..2], .little);
            pos.* += 2;
            return v;
        },
        0xfe => {
            const v = std.mem.readInt(u32, bytes[pos.*..][0..4], .little);
            pos.* += 4;
            return v;
        },
        0xff => {
            const v = std.mem.readInt(u64, bytes[pos.*..][0..8], .little);
            pos.* += 8;
            return v;
        },
        else => return first,
    }
}

const ParsedInput = struct {
    /// Display-order (big-endian) txid hex, 64 chars.
    prev_txid: [64]u8,
    prev_vout: u32,
};

/// Parse just enough of a raw tx to list every input's (txid, vout). The
/// wire order is internal (little-endian); flip to display order so callers
/// can compare directly against a UTXO's `.txid` field.
fn parseInputs(allocator: std.mem.Allocator, hex_str: []const u8) ![]ParsedInput {
    const bytes = try allocator.alloc(u8, hex_str.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex_str);
    var pos: usize = 0;

    pos += 4; // version
    const input_count: usize = @intCast(readVarint(bytes, &pos));
    const inputs = try allocator.alloc(ParsedInput, input_count);
    for (0..input_count) |i| {
        var txid_hex: [64]u8 = undefined;
        var b: usize = 0;
        while (b < 32) : (b += 1) {
            const src = bytes[pos + 31 - b];
            _ = std.fmt.bufPrint(txid_hex[b * 2 ..][0..2], "{x:0>2}", .{src}) catch unreachable;
        }
        pos += 32;
        const vout = std.mem.readInt(u32, bytes[pos..][0..4], .little);
        pos += 4;
        inputs[i] = .{ .prev_txid = txid_hex, .prev_vout = vout };
        const script_len: usize = @intCast(readVarint(bytes, &pos));
        pos += script_len;
        pos += 4; // sequence
    }
    return inputs;
}

test "N-295: a merge's additional contract UTXO is never also selected as P2PKH funding" {
    const allocator = std.testing.allocator;
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, VECTOR_PATH, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const v = parsed.value.object;

    const artifact_json = try std.json.Stringify.valueAlloc(allocator, v.get("artifact").?, .{});
    defer allocator.free(artifact_json);
    var artifact = try types.RunarArtifact.fromJson(allocator, artifact_json);
    defer artifact.deinit();

    const cu_obj = v.get("contractUtxo").?.object;
    const eu_obj = v.get("extraContractUtxo").?.object;
    const fu_obj = v.get("fundingUtxo").?.object;

    const cu = types.UTXO{
        .txid = str(cu_obj, "txid"),
        .output_index = @intCast(cu_obj.get("outputIndex").?.integer),
        .satoshis = cu_obj.get("satoshis").?.integer,
        .script = str(cu_obj, "script"),
    };
    // The extra contract UTXO carries a LARGE satoshi value — bigger than
    // the genuine funding coin — so largest-first coin selection prefers it
    // over the genuine funding candidate if (and only if) the funding
    // filter fails to exclude it.
    const eu = types.UTXO{
        .txid = str(eu_obj, "txid"),
        .output_index = @intCast(eu_obj.get("outputIndex").?.integer),
        .satoshis = 300_000,
        .script = str(eu_obj, "script"),
    };
    // A small genuine P2PKH funding coin — alone, comfortably enough to
    // cover the tx fee.
    const fu = types.UTXO{
        .txid = str(fu_obj, "txid"),
        .output_index = @intCast(fu_obj.get("outputIndex").?.integer),
        .satoshis = 2_000,
        .script = str(fu_obj, "script"),
    };

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex(str(v, "privKeyHex"));
    const addr = try signer.signer().getAddress(allocator);
    defer allocator.free(addr);

    try prov.addUtxo(addr, fu);
    // The indexer ALSO lists the extra contract UTXO under the signer's own
    // address — exactly the scenario this item's brief and N-294 describe.
    try prov.addUtxo(addr, eu);
    try prov.addKnownOutpoint(cu.txid, cu.output_index, cu.script, cu.satoshis);

    var contract = try contract_mod.RunarContract.fromUtxo(allocator, &artifact, cu);
    defer contract.deinit();

    const args = [_]types.StateValue{.{ .int = 0 }};
    const extra = [_]types.UTXO{eu};
    const txid = try contract.call("increment", &args, prov.provider(), signer.signer(), .{
        .additional_contract_inputs = &extra,
    });
    defer allocator.free(txid);

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 1), txs.len);

    const inputs = try parseInputs(allocator, txs[0]);
    defer allocator.free(inputs);

    var occurrences: usize = 0;
    for (inputs) |in| {
        if (std.mem.eql(u8, &in.prev_txid, eu.txid) and in.prev_vout == @as(u32, @intCast(eu.output_index))) {
            occurrences += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), occurrences);
}
