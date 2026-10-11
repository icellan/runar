//! N-038 (R64) — the cross-SDK SIGHASH_SINGLE stateful call vector
//! (`conformance/sdk-call/sighash-single-stateful.json`, TS reference, replayed
//! through @bsv/sdk Spend by `conformance/sdk-call/sdk-call.test.ts`).
//!
//! BIP-143 SINGLE commits hashOutputs to hash256(output[0]) only and zeroes
//! hashSequence, so the contract input's unlocking script depends only on the
//! inputs and the continuation output — not on change or fee policy. The SINGLE
//! method's ABI declares no `_changePKH` / `_changeAmount`, so none is pushed;
//! the change output is still built (it is protected by the funding input's own
//! signature, not by the covenant).
//!
//! Proves: the Zig SDK builds the `bump` call from the vector's contract and
//! funding UTXOs with a byte-identical input-0 unlocking script, the same
//! output 0 (continuation), a change output, and the auto-computed new state.
//! Does NOT prove on-chain acceptance by itself (Zig ships no ScriptVM); the
//! bytes it matches are the ones Spend accepts in the TS test.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const VECTOR_PATH = "../../conformance/sdk-call/sighash-single-stateful.json";

fn hexByteAt(tx_hex: []const u8, byte_off: usize) u8 {
    return std.fmt.parseInt(u8, tx_hex[byte_off * 2 .. byte_off * 2 + 2], 16) catch 0;
}

fn readVarInt(tx_hex: []const u8, cur: *usize) u64 {
    const first = hexByteAt(tx_hex, cur.*);
    cur.* += 1;
    if (first < 0xfd) return first;
    const n: usize = if (first == 0xfd) 2 else if (first == 0xfe) 4 else 8;
    var val: u64 = 0;
    var b: usize = 0;
    while (b < n) : (b += 1) {
        val |= @as(u64, hexByteAt(tx_hex, cur.*)) << @as(u6, @intCast(8 * b));
        cur.* += 1;
    }
    return val;
}

const Parsed = struct {
    input0_unlock: []const u8,
    out0_sats: i64,
    out0_script: []const u8,
    out_count: usize,
};

fn parseTx(tx_hex: []const u8) Parsed {
    var res: Parsed = .{ .input0_unlock = "", .out0_sats = 0, .out0_script = "", .out_count = 0 };
    var cur: usize = 4;
    const in_count = readVarInt(tx_hex, &cur);
    var k: u64 = 0;
    while (k < in_count) : (k += 1) {
        cur += 36;
        const slen: usize = @intCast(readVarInt(tx_hex, &cur));
        if (k == 0) res.input0_unlock = tx_hex[cur * 2 .. (cur + slen) * 2];
        cur += slen + 4;
    }
    res.out_count = @intCast(readVarInt(tx_hex, &cur));
    var val: u64 = 0;
    var b: usize = 0;
    while (b < 8) : (b += 1) val |= @as(u64, hexByteAt(tx_hex, cur + b)) << @as(u6, @intCast(8 * b));
    cur += 8;
    const slen: usize = @intCast(readVarInt(tx_hex, &cur));
    res.out0_sats = @intCast(val);
    res.out0_script = tx_hex[cur * 2 .. (cur + slen) * 2];
    return res;
}

fn str(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    return obj.get(key).?.string;
}

test "N-038: SINGLE stateful call with change reproduces the shared TS vector" {
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

    // The SINGLE method's ABI carries no change params and is not terminal.
    const bump = for (artifact.abi.methods) |m| {
        if (std.mem.eql(u8, m.name, "bump")) break m;
    } else unreachable;
    try std.testing.expectEqual(@as(usize, 1), bump.params.len);
    try std.testing.expectEqualStrings("txPreimage", bump.params[0].name);
    try std.testing.expect(bump.hasContinuation());

    const cu = v.get("contractUtxo").?.object;
    const fu = v.get("fundingUtxo").?.object;
    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex(str(v, "privKeyHex"));
    {
        const addr = try signer.signer().getAddress(allocator);
        defer allocator.free(addr);
        try prov.addUtxo(addr, .{
            .txid = str(fu, "txid"),
            .output_index = @intCast(fu.get("outputIndex").?.integer),
            .satoshis = fu.get("satoshis").?.integer,
            .script = str(fu, "script"),
        });
    }
    var contract = try contract_mod.RunarContract.fromUtxo(allocator, &artifact, .{
        .txid = str(cu, "txid"),
        .output_index = @intCast(cu.get("outputIndex").?.integer),
        .satoshis = cu.get("satoshis").?.integer,
        .script = str(cu, "script"),
    });
    defer contract.deinit();

    const args = [_]types.StateValue{};
    const txid = try contract.call("bump", &args, prov.provider(), signer.signer(), null);
    defer allocator.free(txid);

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 1), txs.len);
    const tx = parseTx(txs[0]);
    try std.testing.expectEqualStrings(str(expected, "input0UnlockingHex"), tx.input0_unlock);
    const out0 = expected.get("output0").?.object;
    try std.testing.expectEqual(out0.get("satoshis").?.integer, tx.out0_sats);
    try std.testing.expectEqualStrings(str(out0, "scriptHex"), tx.out0_script);
    try std.testing.expectEqual(@as(usize, @intCast(expected.get("outputCount").?.integer)), tx.out_count);
    try std.testing.expectEqual(@as(i64, 1), contract.state[0].int);
}
