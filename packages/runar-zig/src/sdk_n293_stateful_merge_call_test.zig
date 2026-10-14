//! N-293 — Zig `call()` on the shared two-phase stateful-merge vector
//! (`conformance/sdk-call/stateful-merge-prepared.json`, TS reference; TS's
//! `call()` is `prepareCall` + sign + `finalizeCall`, and MockProvider
//! Spend-validated all three inputs; re-checked with @bsv/sdk Spend in
//! `conformance/sdk-call/stateful-merge.test.ts`).
//!
//! The scenario: MergeCounter.increment(sig) spends TWO contract UTXOs with
//! the same state (the primary + one `additional_contract_inputs` entry) and
//! one P2PKH funding UTXO, key 0x01, MockProvider fee rate 100 sat/kB.
//!
//! Proves: Zig's one-phase `call()` with the vector's artifact, UTXOs and key
//! broadcasts a tx byte-equal to `expected.referenceTxHex` — so the fee and
//! change (sized from the REAL unlock of every contract input, not a
//! placeholder), both contract inputs' OP_PUSH_TX unlocks and user Sigs, and the
//! funding signature all match TS. The input-0 Sig is RFC 6979 deterministic, so
//! LocalSigner reproduces `expected.primarySignatureHex`.
//! Does NOT prove on-chain acceptance by itself (Zig ships no ScriptVM; the
//! bytes it matches are the ones Spend accepts in the TS test), nor the Zig
//! two-phase prepareCall/finalizeCall merge (N-286), per-input args overrides,
//! or allPrevouts.

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

test "N-293: stateful merge call() reproduces the shared TS merge vector byte for byte" {
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

    // `.int = 0` at a Sig slot = auto-sign (TS `null`).
    const args = [_]types.StateValue{.{ .int = 0 }};
    const extra = [_]types.UTXO{eu};
    const txid = try contract.call("increment", &args, prov.provider(), signer.signer(), .{
        .additional_contract_inputs = &extra,
    });
    defer allocator.free(txid);

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 1), txs.len);
    try std.testing.expectEqualStrings(str(expected, "referenceTxHex"), txs[0]);
    try std.testing.expectEqual(@as(i64, 1), contract.state[0].int);
}
