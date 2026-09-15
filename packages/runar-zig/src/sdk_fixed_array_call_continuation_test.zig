//! A `call()` on a stateful FixedArray contract must build its continuation
//! from the POST-call state.
//!
//! `autoComputeState` talks to the ANF interpreter through two maps keyed by
//! `StateField.name`. For a `FixedArray` field that name is the GROUPED one
//! (`table`), but pass `03b-expand-fixed-arrays` runs before ANF lowering, so
//! the ANF program's properties — and therefore every `load_prop` /
//! `update_prop` in the method body, and every key of the interpreter's result
//! map — are the SYNTHETIC scalar names (`table__0`..`table__3`).
//!
//! Both directions of that boundary were unbridged:
//!   - on the way IN, `current_state.put("table", ...)` is never read, so the
//!     interpreter evaluated `this.table[i]++` against an ABSENT property;
//!   - on the way OUT, `state_map.get("table")` misses, so `self.state[0]`
//!     kept its pre-call value.
//!
//! The continuation output therefore re-commits the PRE-call state: a `bump(0)`
//! that must write `table = [1,0,0,0]` instead deploys `[0,0,0,0]` again. The
//! next spend's covenant check reads the state the method was supposed to have
//! written, so either the increment is silently lost on-chain or the UTXO is
//! unspendable — the same class of defect as `7baf01dd`, one layer up.
//!
//! The peer tiers bridge it explicitly: `flattenFixedArrayState` /
//! `regroupFixedArrayState` in `packages/runar-sdk/src/contract.ts` (:2653,
//! :2689 — "used at the ANF-interpreter boundary, which knows only the expanded
//! scalar property names") and `_flatten_fixed_array_state` /
//! `_regroup_fixed_array_state` in `packages/runar-py/runar/sdk/contract.py`.
//!
//! Zig has NO ScriptVM (see CLAUDE.md), so the proof is a byte assertion on the
//! built continuation output, cross-checked against the TypeScript SDK driven
//! over the SAME artifact: TS deploys 884 bytes ending `6a` + 32 zero bytes and
//! calls `bump(0)` to a 884-byte continuation ending `6a 0100000000000000` + 24
//! zero bytes.
//!
//! The embedded artifact is `examples/ts/fixed-array-write/ArrayWrite.runar.ts`
//! (`table: FixedArray<bigint, 4>`, `public bump(i)` doing `this.table[i]++`)
//! compiled by the TypeScript compiler with `includeIR`, minus `asm` /
//! `buildTimestamp`. Its ANF properties are `table__0`..`table__3`; the state
//! field is the grouped `table`.

const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const contract_mod = @import("sdk_contract.zig");

const RunarContract = contract_mod.RunarContract;

const ARTIFACT_JSON = @embedFile("fixtures/arraywrite-artifact.json");

const DEPLOYER_KEY = "00" ** 31 ++ "07";
const CALLER_KEY = "00" ** 31 ++ "08";

const FUND_SCRIPT = "76a914" ++ "00" ** 20 ++ "88ac";

const ZERO_WORD = "0000000000000000";
const ONE_WORD = "0100000000000000";

// ---------------------------------------------------------------------------
// Minimal raw-tx output parser (no ScriptVM in this tier) — same shape as
// sdk_satcounter_continuation_test.zig.
// ---------------------------------------------------------------------------

const ParsedOutput = struct {
    satoshis: i64,
    /// Locking-script hex; borrows from `tx_hex`.
    script: []const u8,
};

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

fn parseOutputs(allocator: std.mem.Allocator, tx_hex: []const u8) ![]ParsedOutput {
    var cur: usize = 0;
    cur += 4; // version
    const in_count = readVarInt(tx_hex, &cur);
    var k: u64 = 0;
    while (k < in_count) : (k += 1) {
        cur += 32; // prev txid
        cur += 4; // prev vout
        const slen: usize = @intCast(readVarInt(tx_hex, &cur));
        cur += slen; // scriptSig
        cur += 4; // sequence
    }
    const out_count: usize = @intCast(readVarInt(tx_hex, &cur));
    const outs = try allocator.alloc(ParsedOutput, out_count);
    var j: usize = 0;
    while (j < out_count) : (j += 1) {
        var val: u64 = 0;
        var b: usize = 0;
        while (b < 8) : (b += 1) {
            val |= @as(u64, hexByteAt(tx_hex, cur + b)) << @as(u6, @intCast(8 * b));
        }
        cur += 8;
        const slen: usize = @intCast(readVarInt(tx_hex, &cur));
        outs[j] = .{
            .satoshis = @intCast(val),
            .script = tx_hex[cur * 2 .. (cur + slen) * 2],
        };
        cur += slen;
    }
    return outs;
}

/// The 4 leaf words of the `table` state section, i.e. the last 32 bytes of the
/// contract's locking script. `byteLength` is 32 and `tailOffset` is -32, so the
/// section is exactly the script's tail.
fn stateTail(script_hex: []const u8) []const u8 {
    return script_hex[script_hex.len - 64 ..];
}

// ---------------------------------------------------------------------------

test "FixedArray call(): the continuation commits the POST-call state, not the pre-call one" {
    const allocator = std.testing.allocator;

    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();

    var deployer = try signer_mod.LocalSigner.fromHex(DEPLOYER_KEY);
    var caller = try signer_mod.LocalSigner.fromHex(CALLER_KEY);

    {
        const dep_addr = try deployer.signer().getAddress(allocator);
        defer allocator.free(dep_addr);
        try prov.addUtxo(dep_addr, .{ .txid = "aa" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
        const call_addr = try caller.signer().getAddress(allocator);
        defer allocator.free(call_addr);
        try prov.addUtxo(call_addr, .{ .txid = "bb" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }

    // ArrayWrite's constructor takes no arguments; `table` has a `[0n,0n,0n,0n]`
    // initializer.
    const ctor = [_]types.StateValue{};
    var contract = try RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();

    const deploy_txid = try contract.deploy(prov.provider(), deployer.signer(), .{ .satoshis = 1000 });
    defer allocator.free(deploy_txid);

    // Deploy anchor: 884 bytes ending in OP_RETURN + 4 zero words — the value
    // the other six tiers agree on for this fixture.
    {
        const txs = prov.getBroadcastedTxs();
        const outs = try parseOutputs(allocator, txs[0]);
        defer allocator.free(outs);
        try std.testing.expectEqual(@as(usize, 884), outs[0].script.len / 2);
        try std.testing.expectEqualStrings(ZERO_WORD ** 4, stateTail(outs[0].script));
    }

    // bump(0) -> table becomes [1, 0, 0, 0].
    const args = [_]types.StateValue{.{ .int = 0 }};
    const call_txid = try contract.call("bump", &args, prov.provider(), caller.signer(), null);
    defer allocator.free(call_txid);

    // (1) The SDK's own view of the state must have advanced. Regrouped, as the
    // user-facing grouped FixedArray value — `[1, 0, 0, 0]`, not `[0, 0, 0, 0]`.
    try std.testing.expectEqual(@as(usize, 1), contract.state.len);
    try std.testing.expect(contract.state[0] == .array_value);
    const table = contract.state[0].array_value;
    try std.testing.expectEqual(@as(usize, 4), table.len);
    try std.testing.expectEqual(@as(i64, 1), table[0].int);
    try std.testing.expectEqual(@as(i64, 0), table[1].int);
    try std.testing.expectEqual(@as(i64, 0), table[2].int);
    try std.testing.expectEqual(@as(i64, 0), table[3].int);

    // (2) The BYTES that actually go on chain. The continuation output must
    // carry the incremented slot; re-committing the pre-call 32 zero bytes is
    // the defect.
    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 2), txs.len);
    const outs = try parseOutputs(allocator, txs[1]);
    defer allocator.free(outs);
    try std.testing.expect(outs.len >= 1);

    const cont = outs[0].script;
    try std.testing.expectEqual(@as(usize, 884), cont.len / 2);
    // TypeScript, driven over this same artifact, ends its continuation
    // `...6a 0100000000000000` + 24 zero bytes.
    try std.testing.expectEqualStrings(ONE_WORD ++ ZERO_WORD ** 3, stateTail(cont));
    // The state section is the last thing after the final OP_RETURN.
    try std.testing.expectEqualStrings("6a" ++ ONE_WORD ++ ZERO_WORD ** 3, cont[cont.len - 66 ..]);
}

test "FixedArray call(): a second bump of the same slot accumulates on chain" {
    const allocator = std.testing.allocator;

    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    var prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer prov.deinit();

    var deployer = try signer_mod.LocalSigner.fromHex(DEPLOYER_KEY);
    var caller = try signer_mod.LocalSigner.fromHex(CALLER_KEY);

    {
        const dep_addr = try deployer.signer().getAddress(allocator);
        defer allocator.free(dep_addr);
        try prov.addUtxo(dep_addr, .{ .txid = "cc" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
        const call_addr = try caller.signer().getAddress(allocator);
        defer allocator.free(call_addr);
        try prov.addUtxo(call_addr, .{ .txid = "dd" ** 32, .output_index = 0, .satoshis = 500_000, .script = FUND_SCRIPT });
    }

    const ctor = [_]types.StateValue{};
    var contract = try RunarContract.init(allocator, &artifact, &ctor);
    defer contract.deinit();

    const deploy_txid = try contract.deploy(prov.provider(), deployer.signer(), .{ .satoshis = 1000 });
    defer allocator.free(deploy_txid);

    // Two bumps of slot 2. The second one is the real test of the INBOUND half
    // of the boundary: it can only reach 2 if the interpreter read the state the
    // first call wrote. A one-way fix (writing back but never reading) sticks
    // at 1 forever.
    const args = [_]types.StateValue{.{ .int = 2 }};
    const t1 = try contract.call("bump", &args, prov.provider(), caller.signer(), null);
    allocator.free(t1);
    const t2 = try contract.call("bump", &args, prov.provider(), caller.signer(), null);
    allocator.free(t2);

    try std.testing.expect(contract.state[0] == .array_value);
    const table = contract.state[0].array_value;
    try std.testing.expectEqual(@as(i64, 0), table[0].int);
    try std.testing.expectEqual(@as(i64, 0), table[1].int);
    try std.testing.expectEqual(@as(i64, 2), table[2].int);
    try std.testing.expectEqual(@as(i64, 0), table[3].int);

    const txs = prov.getBroadcastedTxs();
    try std.testing.expectEqual(@as(usize, 3), txs.len);
    const outs = try parseOutputs(allocator, txs[2]);
    defer allocator.free(outs);
    const cont = outs[0].script;
    try std.testing.expectEqualStrings(
        ZERO_WORD ** 2 ++ "0200000000000000" ++ ZERO_WORD,
        stateTail(cont),
    );
}
