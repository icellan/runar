//! N-286 — Zig two-phase API (`prepareCall` / `finalizeCall`) on the shared
//! stateful-merge vector (`conformance/sdk-call/stateful-merge-prepared.json`,
//! stamped by the TS SDK; its final tx is re-checked with @bsv/sdk Spend on all
//! three inputs in `conformance/sdk-call/stateful-merge.test.ts`). Two-phase
//! sibling of N-293's one-phase `call()` test; mirrors the Go, Rust, Python and
//! Ruby N-286 tests.
//!
//! The scenario: MergeCounter.increment(sig) spends TWO contract UTXOs with the
//! same state (the primary + one `additional_contract_inputs` entry) and one
//! P2PKH funding UTXO, key 0x01, MockProvider fee rate 100 sat/kB.
//!
//! Proves: Zig's `prepareCall` yields the vector's primary sighash and sig
//! indices [0], and `finalizeCall` with the vector's primary signature
//! broadcasts a tx byte-equal to `expected.referenceTxHex`. So the extra
//! contract input is built and signed at prepare time (its own OP_PUSH_TX
//! preimage and its own Sig, as TS does), the fee/change are sized from the
//! real unlock of every contract input, and finalizeCall rewrites input 0 only.
//! Does NOT prove on-chain acceptance by itself (Zig ships no ScriptVM; the
//! bytes it matches are the ones Spend accepts in the TS test), nor per-input
//! args overrides, allPrevouts, or ANF state auto-compute in prepare (Zig's
//! prepareCallStateful takes the continuation state from `options.new_state`,
//! so the test passes the vector's `newState`).

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

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

test "N-286: stateful merge prepareCall/finalizeCall reproduces the shared TS merge vector byte for byte" {
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
    // Register both contract outpoints so broadcast validation knows every input.
    try prov.addKnownOutpoint(cu.txid, cu.output_index, cu.script, cu.satoshis);
    try prov.addKnownOutpoint(eu.txid, eu.output_index, eu.script, eu.satoshis);

    var contract = try contract_mod.RunarContract.fromUtxo(allocator, &artifact, cu);
    defer contract.deinit();

    // `.int = 0` at a Sig slot = external signature placeholder (TS `null`).
    const args = [_]types.StateValue{.{ .int = 0 }};
    const extra = [_]types.UTXO{eu};
    // The vector stores bigints as decimal strings.
    const new_count = try std.fmt.parseInt(i64, str(v.get("newState").?.object, "count"), 10);
    const new_state = [_]types.StateValue{.{ .int = new_count }};
    var prepared = try contract.prepareCall("increment", &args, prov.provider(), signer.signer(), .{
        .additional_contract_inputs = &extra,
        .new_state = &new_state,
    });
    defer prepared.deinit(allocator);

    const want_indices = expected.get("sigIndices").?.array.items;
    try std.testing.expectEqual(want_indices.len, prepared.sig_indices.len);
    try std.testing.expectEqual(@as(usize, @intCast(want_indices[0].integer)), prepared.sig_indices[0]);
    try std.testing.expectEqual(@as(usize, 1), prepared.sighashes.len);
    try std.testing.expectEqualStrings(str(expected, "sighash"), prepared.sighashes[0]);

    const sigs = [_][]const u8{str(expected, "primarySignatureHex")};
    const txid = try contract.finalizeCall(&prepared, &sigs, prov.provider());
    defer allocator.free(txid);

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 1), txs.len);
    try std.testing.expectEqualStrings(str(expected, "referenceTxHex"), txs[0]);
}
