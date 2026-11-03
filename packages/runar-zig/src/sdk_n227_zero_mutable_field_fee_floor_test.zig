//! N-227 (port of sdk:ts N-085): a zero-mutable-field `StatefulSmartContract`
//! call underpays MockProvider's 100 sat/KB fee floor.
//!
//! Unlike TS/Go/Rust/Python/Ruby (before each tier's N-227 fix), the Zig
//! `call()` entry point does NOT split "stateful" vs "stateless" for the
//! fee/change sizing pass on `isStateful`. It gates the whole OP_PUSH_TX
//! convergence path on `parent_stateful` instead (see sdk_contract.zig,
//! `const no_state_continuation = parent_stateful and !is_stateful;` and the
//! comment above it): a zero-mutable-field StatefulSmartContract — which IS
//! `parent_stateful` but not `is_stateful` — is folded into the SAME rebuild
//! block a continuation-bearing stateful contract uses (first pass with a
//! correctly-sized placeholder, rebuild with the REAL unlock, second pass).
//! There is no separate "stateless" branch that skips the rebuild, so this
//! tier never had the N-085 class of bug.
//!
//! This fixture is `AllReadonlyCleanstack` (same contract N-085/N-227 use in
//! every other tier), compiled with the Zig compiler
//! (`zig-out/bin/runar-zig --source AllReadonlyCleanstack.runar.ts`) and
//! checked in as `fixtures/n227-all-readonly-cleanstack-artifact.json`.
//!
//! Proves: the Zig SDK's `claim()` call on a zero-mutable-field
//! StatefulSmartContract broadcasts a tx whose actual fee (computed from the
//! REAL broadcast bytes this test parses itself: sum of known input
//! satoshis minus sum of output satoshis) meets the 100 sat/KB floor
//! `MockProvider`'s fee rate reports — i.e. this tier is ALREADY correct, no
//! production fix was needed. A one-line self-mutation of the fee
//! comparison below (flip `>=` to `<`) shows the assertion is not vacuous.
//!
//! Does NOT prove: on-chain acceptance (Zig ships no ScriptVM — see
//! CLAUDE.md); nor anything about TypeScript (fixed separately, N-085), Go,
//! Rust, Python, Ruby or Java, each a separate item slot; nor the merge
//! (`additionalContractInputs`) case for a zero-mutable-field contract,
//! which is out of scope for this test — Zig already supports it via the
//! same unified path (its own per-input rebuild loop; see sdk_contract.zig
//! around the "Build & insert real unlocks for each additional contract
//! input" comment), unlike the five tiers this item adds a fail-closed
//! guard to.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const ARTIFACT_JSON = @embedFile("fixtures/n227-all-readonly-cleanstack-artifact.json");
const KEY = "00" ** 31 ++ "03";
const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

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

const ParsedTx = struct {
    input_count: usize,
    total_output_satoshis: i64,
};

fn parseTx(allocator: std.mem.Allocator, hex_str: []const u8) !ParsedTx {
    const bytes = try allocator.alloc(u8, hex_str.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex_str);
    var pos: usize = 0;

    pos += 4; // version
    const input_count: usize = @intCast(readVarint(bytes, &pos));
    for (0..input_count) |_| {
        pos += 32 + 4; // prev txid + prev index
        const script_len: usize = @intCast(readVarint(bytes, &pos));
        pos += script_len;
        pos += 4; // sequence
    }
    const output_count: usize = @intCast(readVarint(bytes, &pos));
    var total_output_satoshis: i64 = 0;
    for (0..output_count) |_| {
        total_output_satoshis += std.mem.readInt(i64, bytes[pos..][0..8], .little);
        pos += 8;
        const script_len: usize = @intCast(readVarint(bytes, &pos));
        pos += script_len;
    }

    return .{ .input_count = input_count, .total_output_satoshis = total_output_satoshis };
}

test "N-227: claim() on AllReadonlyCleanstack pays the fee floor" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    // Sanity on the premise: zero mutable state fields, but still a real
    // StatefulSmartContract (auto-injects checkPreimage).
    try std.testing.expectEqualStrings("StatefulSmartContract", artifact.parent_class);
    try std.testing.expectEqual(@as(usize, 0), artifact.state_fields.len);

    var prov = provider_mod.MockProvider.init(allocator, "testnet"); // validate_broadcasts default-on
    defer prov.deinit();
    var signer = try signer_mod.LocalSigner.fromHex(KEY);

    const addr = try signer.signer().getAddress(allocator);
    defer allocator.free(addr);
    const pub_key = try signer.signer().getPublicKey(allocator);
    defer allocator.free(pub_key);
    try prov.addUtxo(addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 100_000, .script = FUND_SCRIPT });

    const ctor = [_]types.StateValue{.{ .bytes = pub_key }};
    var contract = try contract_mod.RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();

    const deploy_txid = try contract.deploy(prov.provider(), signer.signer(), .{ .satoshis = 5_000, .change_address = addr });
    defer allocator.free(deploy_txid);

    // claim(sig, txPreimage): both auto-resolved (int(0) => SDK fills Sig +
    // SigHashPreimage). is_stateful is false here, so neither param is
    // hidden from the caller — mirrors the TS N-085 repro's [null, null].
    const args = [_]types.StateValue{ .{ .int = 0 }, .{ .int = 0 } };
    const call_txid = try contract.call("claim", &args, prov.provider(), signer.signer(), .{});
    defer allocator.free(call_txid);

    const txs = prov.getBroadcastedTxs();
    const call_hex = txs[txs.len - 1];
    const parsed = try parseTx(allocator, call_hex);

    // Total input value: the contract's own deployed UTXO (5000 sats) plus,
    // if more than one input is present, the ONE funding UTXO this test
    // registered (100000 sats) — this test controls the entire UTXO
    // universe, so the input count alone determines which UTXOs were spent.
    var total_in: i64 = 5_000;
    if (parsed.input_count > 1) total_in += 100_000;

    const actual_fee = total_in - parsed.total_output_satoshis;
    const fee_rate = try prov.provider().getFeeRate();
    const tx_size_bytes: i64 = @intCast(call_hex.len / 2);
    const required_fee: i64 = @divFloor(tx_size_bytes * fee_rate + 999, 1000);

    // Self-mutation check for the dispatcher's mutation review: flipping
    // this to `actual_fee < required_fee` makes the assertion fail, proving
    // it is not vacuous.
    try std.testing.expect(actual_fee >= required_fee);
}
