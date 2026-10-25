//! N-412 — a STATELESS contract method that takes the auto-injected intent
//! witness `_prevOutScript_0`, on the shared vector
//! `conformance/sdk-call/stateless-witness.json` (stamped by the TS SDK, whose
//! MockProvider Spend-validated every input; re-checked with @bsv/sdk Spend —
//! including a tampered/omitted witness push — in
//! `conformance/sdk-call/stateless-witness.test.ts`). Mirrors the Go, Rust,
//! Python, Ruby and Java N-412 tests.
//!
//! Proves: Zig's `call` (no-Sig `peek`, Sig `spend`) and `prepareCall` +
//! `finalizeCall` (`spend`) push `<declared args> <witness> <selector>` on
//! input 0 and broadcast a tx byte-equal to the TS reference. Before N-412
//! both entry points refused the method (N-149's
//! StatelessIntentWitnessUnsupported). Does NOT prove on-chain acceptance by
//! itself (Zig ships no ScriptVM; the bytes it matches are the ones Spend
//! accepts in the TS test), nor `_serialisedOutputs` on a stateless method
//! (the compiler refuses requireOutputP2PKH outside StatefulSmartContract).

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const VECTOR_PATH = "../../conformance/sdk-call/stateless-witness.json";

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

const Scenario = enum { call_peek, call_spend, prepare_finalize_spend };

fn run(scenario: Scenario) !void {
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
    try contract.setPrevOutScript(0, str(v, "prevOutScriptHex"));

    // `.int = 0` at a Sig slot = auto-sign / external signature placeholder (TS `null`).
    const spend_args = [_]types.StateValue{ .{ .int = 0 }, .{ .bytes = str(v, "pubKeyHex") } };
    const peek_args = [_]types.StateValue{.{ .int = 5 }};

    var want: std.json.ObjectMap = undefined;
    switch (scenario) {
        .call_peek => {
            want = expected.get("peek").?.object;
            const txid = try contract.call("peek", &peek_args, prov.provider(), signer.signer(), null);
            allocator.free(txid);
        },
        .call_spend => {
            want = expected.get("spend").?.object;
            const txid = try contract.call("spend", &spend_args, prov.provider(), signer.signer(), null);
            allocator.free(txid);
        },
        .prepare_finalize_spend => {
            want = expected.get("spend").?.object;
            var prepared = try contract.prepareCall("spend", &spend_args, prov.provider(), signer.signer(), null);
            defer prepared.deinit(allocator);
            try std.testing.expectEqual(@as(usize, 1), prepared.sig_indices.len);
            try std.testing.expectEqual(@as(usize, 0), prepared.sig_indices[0]);
            const sigs = [_][]const u8{str(want, "signatureHex")};
            const txid = try contract.finalizeCall(&prepared, &sigs, prov.provider());
            allocator.free(txid);
        },
    }

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 1), txs.len);
    try std.testing.expect(std.mem.indexOf(u8, txs[0], str(want, "input0UnlockingHex")) != null);
    try std.testing.expectEqualStrings(str(want, "referenceTxHex"), txs[0]);
}

test "N-412: stateless call(peek) pushes <x> <witness> <selector>, byte-equal to the TS vector" {
    try run(.call_peek);
}

test "N-412: stateless call(spend) pushes <sig> <pubKey> <witness> <selector>, byte-equal to the TS vector" {
    try run(.call_spend);
}

test "N-412: stateless prepareCall/finalizeCall(spend) matches the TS vector" {
    try run(.prepare_finalize_spend);
}
